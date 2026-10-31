package wireguard

import (
	"fmt"
	"log/slog"
	"net"
	"slices"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EnsurePeer creates a new peer or rotates keys for an existing one.
//
// Persistence is write-ahead: the new record is written to bbolt BEFORE the
// device is mutated. If the device write fails, the persist is rolled back so
// device, in-memory store, and bbolt converge to the pre-call state. If the
// process crashes between persist and configureDevice, startup reconcile
// restores the device from the store. This eliminates the classic
// "device-changed but bbolt-not-yet" window where a crash would either lose a
// peer (new peer case) or strand a client on a now-unrecoverable private key
// (rotation case).
//
// Everything runs under s.mu, including the bbolt I/O. Peer create/rotate is
// rare (orchestrator-driven, not data-path), so holding the lock through a
// short fsync is the right trade-off for correctness.
func (s *WireGuardService) EnsurePeer(peerID string, expiresAt *time.Time, addressFamilies []string) (PeerInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if record, ok := s.store.Get(peerID); ok {
		if expiresAt == nil && record.ExpiresAt != nil && !time.Now().Before(*record.ExpiresAt) {
			return PeerInfo{}, ErrPeerExpired
		}
		return s.rotatePeer(peerID, record, expiresAt)
	}
	return s.createPeer(peerID, expiresAt, addressFamilies)
}

// createPeer adds a brand-new peer. Must be called with s.mu held.
func (s *WireGuardService) createPeer(peerID string, expiresAt *time.Time, addressFamilies []string) (PeerInfo, error) {
	families, err := s.ValidateAddressFamilies(addressFamilies)
	if err != nil {
		return PeerInfo{}, err
	}

	allowedIPs, err := s.allocateIPs(families)
	if err != nil {
		return PeerInfo{}, err
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		s.releaseAllocatedIPs(allowedIPs)
		return PeerInfo{}, err
	}
	publicKey := privateKey.PublicKey()
	presharedKey, err := wgtypes.GenerateKey()
	if err != nil {
		s.releaseAllocatedIPs(allowedIPs)
		return PeerInfo{}, err
	}

	rec := PeerRecord{
		PeerID:       peerID,
		PublicKey:    publicKey,
		PresharedKey: presharedKey,
		AllowedIPs:   allowedIPs,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    expiresAt,
	}

	// Write-ahead persist: bbolt is updated before the device. If this fails,
	// nothing has changed yet — return the error and free the reserved IP.
	if err := s.store.PersistPut(rec); err != nil {
		s.releaseAllocatedIPs(allowedIPs)
		return PeerInfo{}, fmt.Errorf(errSavePeerStoreFmt, ErrPeerStore, err)
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey:                   publicKey,
		PresharedKey:                &presharedKey,
		AllowedIPs:                  allowedIPs,
		ReplaceAllowedIPs:           true,
		PersistentKeepaliveInterval: keepaliveInterval(),
	}
	if err := s.configureDevice(wgtypes.Config{Peers: []wgtypes.PeerConfig{peerConfig}}); err != nil {
		if s.deviceChangeUncertain(err) {
			// The peer stays in the store and reaches the device through
			// reconcile. The caller got no keys; retrying rotates them.
			s.store.Set(rec)
			return PeerInfo{}, err
		}
		// Rollback persist (best-effort). On rollback failure the peer remains
		// in bbolt as an orphan; startup reconcile will install it on the
		// device next time and it becomes a normal (unused) peer the operator
		// can delete via the API.
		rbErr := s.store.PersistDeleteBatch(peerID)
		if rbErr != nil {
			slog.Error("rollback persist after configureDevice failure",
				"peer_id", peerID, "rollback_error", rbErr, "device_error", err)
		}
		s.notifyRollback(rollbackOpCreate, rbErr)
		s.releaseAllocatedIPs(allowedIPs)
		return PeerInfo{}, err
	}

	s.store.Set(rec)

	allowedIPsStr := make([]string, len(allowedIPs))
	for i := range allowedIPs {
		allowedIPsStr[i] = allowedIPs[i].String()
	}
	return PeerInfo{
		PeerID:          peerID,
		PublicKey:       publicKey.String(),
		PrivateKey:      privateKey.String(),
		PresharedKey:    presharedKey.String(),
		AllowedIPs:      allowedIPsStr,
		AddressFamilies: families,
		Rotated:         false,
	}, nil
}

// releaseAllocatedIPs returns addresses to their pool. Must be called with s.mu held.
func (s *WireGuardService) releaseAllocatedIPs(ips []net.IPNet) {
	for _, aip := range ips {
		a := addrFromIP(aip.IP)
		if a.Is4() && s.pool4 != nil {
			s.pool4.release(a)
		} else if a.Is6() && s.pool6 != nil {
			s.pool6.release(a)
		}
	}
}

// DeletePeer removes a peer and returns the AllowedIPs that were freed (for
// audit logging). Like create and rotate it is write-ahead and runs entirely
// under s.mu: the bbolt record is deleted first, then the device peer; if the
// device call fails the record is restored. A crash in between leaves the
// peer only on the device, and startup reconcile removes it.
func (s *WireGuardService) DeletePeer(peerID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.store.Get(peerID)
	if !ok {
		return nil, ErrPeerNotFound
	}
	if err := s.store.PersistDeleteBatch(peerID); err != nil {
		return nil, fmt.Errorf(errSavePeerStoreFmt, ErrPeerStore, err)
	}
	remove := wgtypes.PeerConfig{PublicKey: record.PublicKey, Remove: true}
	if err := s.configureDevice(wgtypes.Config{Peers: []wgtypes.PeerConfig{remove}}); err != nil {
		if s.deviceChangeUncertain(err) {
			s.forgetPeerLocked(record)
			return nil, err
		}
		rbErr := s.store.PersistPut(record)
		if rbErr != nil {
			slog.Error("rollback persist after delete failure",
				"peer_id", peerID, "rollback_error", rbErr, "device_error", err)
		}
		s.notifyRollback(rollbackOpDelete, rbErr)
		return nil, err
	}
	s.forgetPeerLocked(record)
	out := make([]string, len(record.AllowedIPs))
	for i := range record.AllowedIPs {
		out[i] = record.AllowedIPs[i].String()
	}
	return out, nil
}

// forgetPeerLocked drops a peer that is already gone from bbolt and the device
// from the in-memory store and frees its addresses. Must be called with s.mu held.
func (s *WireGuardService) forgetPeerLocked(record PeerRecord) {
	s.store.Delete(record.PeerID)
	s.releaseAllocatedIPs(record.AllowedIPs)
}

func appendIfNotPresent(slice []string, v string) []string {
	if slices.Contains(slice, v) {
		return slice
	}
	return append(slice, v)
}

// rotatePeer rotates keys for an existing peer using write-ahead persist.
// Must be called with s.mu held.
//
// Order: generate new keys → persist new record → configureDevice (atomic
// remove-old + add-new) → in-memory store.Set. If configureDevice fails the
// persist is rolled back to the original record. If the process crashes between
// persist and configureDevice, startup reconcile installs the new key on the
// device — the client (which already received the new private key) keeps
// working. This avoids the previous failure mode where a crash after a
// successful configureDevice but before persist would, on restart, restore the
// OLD key from bbolt and permanently lock out the client holding the new
// private key.
func (s *WireGuardService) rotatePeer(peerID string, record PeerRecord, expiresAt *time.Time) (PeerInfo, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return PeerInfo{}, err
	}
	publicKey := privateKey.PublicKey()
	presharedKey, err := wgtypes.GenerateKey()
	if err != nil {
		return PeerInfo{}, err
	}

	effectiveExpiresAt := expiresAt
	if effectiveExpiresAt == nil {
		effectiveExpiresAt = record.ExpiresAt
	}
	newRec := PeerRecord{
		PeerID:       peerID,
		PublicKey:    publicKey,
		PresharedKey: presharedKey,
		AllowedIPs:   record.AllowedIPs,
		CreatedAt:    record.CreatedAt,
		ExpiresAt:    effectiveExpiresAt,
	}

	// Write-ahead persist: replace the bbolt record with the new keys before
	// touching the device. If this fails, nothing has changed.
	if err := s.store.PersistPut(newRec); err != nil {
		return PeerInfo{}, fmt.Errorf(errSavePeerStoreFmt, ErrPeerStore, err)
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{PublicKey: record.PublicKey, Remove: true},
			{
				PublicKey:                   publicKey,
				PresharedKey:                &presharedKey,
				AllowedIPs:                  record.AllowedIPs,
				ReplaceAllowedIPs:           true,
				PersistentKeepaliveInterval: keepaliveInterval(),
			},
		},
	}
	if err := s.configureDevice(config); err != nil {
		if s.deviceChangeUncertain(err) {
			s.store.Set(newRec)
			return PeerInfo{}, err
		}
		// Rollback persist to the old record. Best-effort: on rollback failure
		// bbolt holds the new key while the device still has the old one.
		// Startup reconcile will then install the new key — orphaning the old
		// peer on the device is impossible because we did not configureDevice.
		rbErr := s.store.PersistPut(record)
		if rbErr != nil {
			slog.Error("rollback persist after rotation failure",
				"peer_id", peerID, "rollback_error", rbErr, "device_error", err)
		}
		s.notifyRollback(rollbackOpRotate, rbErr)
		return PeerInfo{}, err
	}

	s.store.Set(newRec)

	allowedIPsStr := make([]string, len(record.AllowedIPs))
	peerFamilies := make([]string, 0, 2)
	for i := range record.AllowedIPs {
		allowedIPsStr[i] = record.AllowedIPs[i].String()
		if record.AllowedIPs[i].IP.To4() != nil {
			peerFamilies = appendIfNotPresent(peerFamilies, FamilyIPv4)
		} else {
			peerFamilies = appendIfNotPresent(peerFamilies, FamilyIPv6)
		}
	}
	return PeerInfo{
		PeerID:          peerID,
		PublicKey:       publicKey.String(),
		PrivateKey:      privateKey.String(),
		PresharedKey:    presharedKey.String(),
		AllowedIPs:      allowedIPsStr,
		AddressFamilies: peerFamilies,
		Rotated:         true,
	}, nil
}

// allocateIPs allocates one address per requested family. families must be
// validated (e.g. via ValidateAddressFamilies). Must be called with s.mu held.
func (s *WireGuardService) allocateIPs(families []string) ([]net.IPNet, error) {
	if s.pool4 == nil && s.pool6 == nil {
		if err := s.initPools(); err != nil {
			return nil, err
		}
	}
	wantIPv4, wantIPv6 := familiesRequested(families)
	var out []net.IPNet
	if wantIPv4 && s.pool4 != nil {
		a, err := s.pool4.allocate()
		if err != nil {
			return nil, err
		}
		out = append(out, hostIPNet(a))
	}
	if wantIPv6 && s.pool6 != nil {
		a, err := s.pool6.allocate()
		if err != nil {
			// Return the IPv4 address reserved above so a dual-stack request
			// that fails on IPv6 doesn't leak it.
			s.releaseAllocatedIPs(out)
			return nil, err
		}
		out = append(out, hostIPNet(a))
	}
	return out, nil
}

func familiesRequested(families []string) (wantIPv4, wantIPv6 bool) {
	for _, f := range families {
		if f == FamilyIPv4 {
			wantIPv4 = true
		}
		if f == FamilyIPv6 {
			wantIPv6 = true
		}
	}
	return wantIPv4, wantIPv6
}

func keepaliveInterval() *time.Duration {
	interval := 25 * time.Second
	return &interval
}
