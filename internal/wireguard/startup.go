package wireguard

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func initPersistStore(svc *WireGuardService) error {
	if svc.persistPath == "" {
		return nil
	}
	info, err := os.Stat(svc.persistPath)
	if err == nil && info.IsDir() {
		return fmt.Errorf("wireguard.peer_store_file must not be a directory: %s", svc.persistPath)
	}
	if err := os.MkdirAll(filepath.Dir(svc.persistPath), 0o700); err != nil {
		return fmt.Errorf("create peer store directory: %w", err)
	}
	// OpenFile creates the file on first start; a missing file is an empty store.
	if err := svc.store.OpenFile(svc.persistPath); err != nil {
		return fmt.Errorf("load peer store: %w", err)
	}
	// Check the store against the config before touching the device: a
	// mismatch is almost always a config change or typo, and the node never
	// deletes peers to resolve it.
	if err := svc.validateStoredPeers(); err != nil {
		return err
	}
	if err := svc.reconcileStoreWithDevice(); err != nil {
		return fmt.Errorf("reconcile peer store with device: %w", err)
	}
	// Remove expired peers synchronously so they are not visible on the device
	// or in the store before the HTTP server starts accepting requests.
	svc.cleanupExpiredPeers()
	return nil
}

// reconcileStoreWithDevice synchronises the device with the store at startup.
// The store is the source of truth: peers in the store but not on the device
// are added (e.g. after a reboot), and peers on the device whose public keys
// are not in the store are removed (orphans from a crash mid-write or manual
// `wg set` calls). Without the latter direction, a crash window between
// configureDevice and PersistPut leaves an unmanaged peer on the device that
// is invisible to the store and can collide with future allocations.
func (s *WireGuardService) reconcileStoreWithDevice() error {
	device, err := s.deviceWithTimeout()
	if err != nil {
		return err
	}
	onDevice := make(map[wgtypes.Key]bool)
	for i := range device.Peers {
		onDevice[device.Peers[i].PublicKey] = true
	}
	inStore := make(map[wgtypes.Key]bool)
	var toAdd []wgtypes.PeerConfig
	s.store.ForEach(func(rec PeerRecord) {
		inStore[rec.PublicKey] = true
		if !onDevice[rec.PublicKey] {
			psk := rec.PresharedKey
			toAdd = append(toAdd, wgtypes.PeerConfig{
				PublicKey:                   rec.PublicKey,
				PresharedKey:                &psk,
				AllowedIPs:                  rec.AllowedIPs,
				ReplaceAllowedIPs:           true,
				PersistentKeepaliveInterval: keepaliveInterval(),
			})
		}
	})
	var toRemove []wgtypes.PeerConfig
	for i := range device.Peers {
		if !inStore[device.Peers[i].PublicKey] {
			slog.Warn("reconcile: removing orphan peer from device",
				"public_key", device.Peers[i].PublicKey.String())
			toRemove = append(toRemove, wgtypes.PeerConfig{
				PublicKey: device.Peers[i].PublicKey,
				Remove:    true,
			})
		}
	}
	peers := slices.Concat(toAdd, toRemove)
	if len(peers) == 0 {
		return nil
	}
	return s.configureDevice(wgtypes.Config{Peers: peers})
}

// reconcileStoreWithSubnets removes from store and from the device any record whose allowed_ips
// are not entirely within the current config subnets (subnet4/subnet6).
// Returns the peer IDs that were successfully removed.
// validateStoredPeers refuses to start when stored peers no longer fit the
// config: an address outside the configured subnets, the server address, or
// an address held by two peers. The node used to delete out-of-subnet peers
// here, which turned a subnet typo into permanent loss of every peer.
func (s *WireGuardService) validateStoredPeers() error {
	owner := make(map[string]string)
	for _, ip := range []net.IP{s.serverIP4, s.serverIP6} {
		if ip != nil {
			owner[ip.String()] = "the server"
		}
	}
	var outside []string
	var conflicts []string
	s.store.ForEach(func(rec PeerRecord) {
		if !s.recordAllowedIPsInSubnets(rec) {
			outside = append(outside, rec.PeerID)
		}
		for _, aip := range rec.AllowedIPs {
			key := aip.IP.String()
			if prev, ok := owner[key]; ok {
				conflicts = append(conflicts, fmt.Sprintf("%s is used by peer %s and %s", key, rec.PeerID, prev))
				continue
			}
			owner[key] = "peer " + rec.PeerID
		}
	})
	if len(outside) > 0 {
		return fmt.Errorf("%d stored peer(s) have addresses outside the configured subnets (first: %s); "+
			"no peers were changed. Restore the previous wireguard.subnet/subnet6, or delete these peers "+
			"through the API before changing the subnets", len(outside), outside[0])
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("peer store has %d address conflict(s) (first: %s); no peers were changed. "+
			"Delete the conflicting peers through the API or fix wireguard.server_ip/server_ip6", len(conflicts), conflicts[0])
	}
	return nil
}

func (s *WireGuardService) recordAllowedIPsInSubnets(rec PeerRecord) bool {
	for _, aip := range rec.AllowedIPs {
		in4 := s.subnet4 != nil && s.subnet4.Contains(aip.IP)
		in6 := s.subnet6 != nil && s.subnet6.Contains(aip.IP)
		if !in4 && !in6 {
			return false
		}
	}
	return true
}

// initPools builds the address pools from the subnets, the server addresses
// and the stored peers. Call before the service handles requests.
func (s *WireGuardService) initPools() error {
	s.pool4, s.pool6 = nil, nil
	if s.subnet4 != nil {
		p, err := newPoolForSubnet(s.subnet4, s.serverIP4)
		if err != nil {
			return fmt.Errorf("wireguard.subnet: %w", err)
		}
		s.pool4 = p
	}
	if s.subnet6 != nil {
		p, err := newPoolForSubnet(s.subnet6, s.serverIP6)
		if err != nil {
			return fmt.Errorf("wireguard.subnet6: %w", err)
		}
		s.pool6 = p
	}
	s.store.ForEach(func(rec PeerRecord) {
		for _, aip := range rec.AllowedIPs {
			a := addrFromIP(aip.IP)
			if a.Is4() && s.pool4 != nil {
				s.pool4.markUsed(a)
			} else if a.Is6() && s.pool6 != nil {
				s.pool6.markUsed(a)
			}
		}
	})
	return nil
}

func newPoolForSubnet(subnet *net.IPNet, server net.IP) (*ipPool, error) {
	prefix, err := prefixFromIPNet(subnet)
	if err != nil {
		return nil, err
	}
	return newIPPool(prefix, addrFromIP(server))
}
