package wireguard

import (
	"time"

	"github.com/wgkeeper/wgkeeper-node/internal/version"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var serverStart = time.Now()

type Stats struct {
	Service   ServiceInfo   `json:"service"`
	WireGuard WireGuardInfo `json:"wireguard"`
	Peers     PeerStats     `json:"peers"`
	StartedAt string        `json:"startedAt"`
}

type ServiceInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type PeerStats struct {
	Possible int `json:"possible"`
	Issued   int `json:"issued"`
	Active   int `json:"active"`
}

type WireGuardInfo struct {
	Interface       string   `json:"interface"`
	ListenPort      int      `json:"listenPort"`
	Subnets         []string `json:"subnets"`
	ServerIPs       []string `json:"serverIps"`
	AddressFamilies []string `json:"addressFamilies"` // what the node supports, e.g. ["IPv4", "IPv6"]
}

// PeerListItem is a minimal peer entry for list responses.
type PeerListItem struct {
	PeerID          string     `json:"peerId"`
	AllowedIPs      []string   `json:"allowedIPs"`
	AddressFamilies []string   `json:"addressFamilies"` // e.g. ["IPv4"] or ["IPv4", "IPv6"]
	PublicKey       string     `json:"publicKey"`
	Active          bool       `json:"active"`
	LastHandshakeAt *time.Time `json:"lastHandshakeAt"`
	CreatedAt       string     `json:"createdAt"`
	ExpiresAt       *string    `json:"expiresAt,omitempty"` // RFC3339, empty if permanent
}

// PeerDetail extends PeerListItem with traffic stats for single-peer responses.
type PeerDetail struct {
	PeerListItem
	ReceiveBytes  int64 `json:"receiveBytes"`
	TransmitBytes int64 `json:"transmitBytes"`
}

// WireGuardSnapshot is an aggregated view of kernel-level WireGuard state for
// observability. Per-peer breakdown is intentionally absent — exposing it as
// labelled metrics would blow up cardinality on any non-trivial deployment.
type WireGuardSnapshot struct {
	// ReceiveBytesTotal is the sum of ReceiveBytes across all peers as
	// reported by the kernel via netlink. Monotonically increasing under
	// normal operation; resets when the interface is recreated.
	ReceiveBytesTotal int64
	// TransmitBytesTotal mirrors ReceiveBytesTotal for transmitted bytes.
	TransmitBytesTotal int64
	// StalePeers counts peers whose last handshake is older than
	// HandshakeStaleThreshold or has never happened. Gauge — useful as a
	// degradation signal independent of the tighter "active" peer count
	// surfaced by /stats.
	StalePeers int
}

// WireGuardSnapshot returns aggregated kernel-level metrics. Reuses the
// short-lived device cache so a tight scrape interval does not hammer netlink.
func (s *WireGuardService) WireGuardSnapshot() (WireGuardSnapshot, error) {
	dev, err := s.cachedDevice()
	if err != nil {
		return WireGuardSnapshot{}, err
	}
	now := time.Now()
	var snap WireGuardSnapshot
	for _, p := range dev.Peers {
		snap.ReceiveBytesTotal += p.ReceiveBytes
		snap.TransmitBytesTotal += p.TransmitBytes
		if p.LastHandshakeTime.IsZero() || now.Sub(p.LastHandshakeTime) > HandshakeStaleThreshold {
			snap.StalePeers++
		}
	}
	return snap, nil
}

func (s *WireGuardService) Stats() (Stats, error) {
	peersPossible, err := s.possiblePeerCountTotal()
	if err != nil {
		return Stats{}, err
	}

	device, err := s.cachedDevice()
	if err != nil {
		return Stats{}, err
	}

	now := time.Now()
	active := 0
	for _, peer := range device.Peers {
		if peer.LastHandshakeTime.IsZero() {
			continue
		}
		if now.Sub(peer.LastHandshakeTime) <= activePeerWindow {
			active++
		}
	}

	subnets := make([]string, 0, 2)
	serverIPs := make([]string, 0, 2)
	if s.subnet4 != nil {
		subnets = append(subnets, s.subnet4.String())
		serverIPs = append(serverIPs, s.serverIP4.String())
	}
	if s.subnet6 != nil {
		subnets = append(subnets, s.subnet6.String())
		serverIPs = append(serverIPs, s.serverIP6.String())
	}
	nodeFamilies := s.NodeAddressFamilies()

	return Stats{
		Service: ServiceInfo{
			Name:    version.Name,
			Version: version.Version,
		},
		WireGuard: WireGuardInfo{
			Interface:       s.deviceName,
			ListenPort:      device.ListenPort,
			Subnets:         subnets,
			ServerIPs:       serverIPs,
			AddressFamilies: nodeFamilies,
		},
		Peers: PeerStats{
			Possible: peersPossible,
			Issued:   s.store.Len(),
			Active:   active,
		},
		StartedAt: serverStart.UTC().Format(time.RFC3339),
	}, nil
}

func (s *WireGuardService) ListPeers(offset, limit int) ([]PeerListItem, int, error) {
	snap, err := s.cachedSnapshot()
	if err != nil {
		return nil, 0, err
	}
	records, total := s.store.ListPaginated(offset, limit)
	now := time.Now()
	list := make([]PeerListItem, len(records))
	for i, rec := range records {
		devicePeer, _ := snap.peer(rec.PublicKey)
		list[i] = peerRecordToListItem(rec, devicePeer, now)
	}
	return list, total, nil
}

func (s *WireGuardService) GetPeer(peerID string) (*PeerDetail, error) {
	record, ok := s.store.Get(peerID)
	if !ok {
		return nil, ErrPeerNotFound
	}
	snap, err := s.cachedSnapshot()
	if err != nil {
		return nil, err
	}
	devicePeer, _ := snap.peer(record.PublicKey)
	now := time.Now()
	item := peerRecordToListItem(record, devicePeer, now)
	detail := &PeerDetail{
		PeerListItem:  item,
		ReceiveBytes:  devicePeer.ReceiveBytes,
		TransmitBytes: devicePeer.TransmitBytes,
	}
	return detail, nil
}

func peerRecordToListItem(rec PeerRecord, devicePeer wgtypes.Peer, now time.Time) PeerListItem {
	var lastHandshake *time.Time
	active := false
	if !devicePeer.LastHandshakeTime.IsZero() {
		t := devicePeer.LastHandshakeTime
		lastHandshake = &t
		if now.Sub(devicePeer.LastHandshakeTime) <= activePeerWindow {
			active = true
		}
	}
	createdAt := rec.CreatedAt.UTC().Format(time.RFC3339)
	if rec.CreatedAt.IsZero() {
		createdAt = ""
	}
	var expiresAt *string
	if rec.ExpiresAt != nil {
		s := rec.ExpiresAt.UTC().Format(time.RFC3339)
		expiresAt = &s
	}
	allowedIPs := make([]string, len(rec.AllowedIPs))
	families := make([]string, 0, 2)
	for i := range rec.AllowedIPs {
		allowedIPs[i] = rec.AllowedIPs[i].String()
		if rec.AllowedIPs[i].IP.To4() != nil {
			families = appendIfNotPresent(families, FamilyIPv4)
		} else {
			families = appendIfNotPresent(families, FamilyIPv6)
		}
	}
	return PeerListItem{
		PeerID:          rec.PeerID,
		AllowedIPs:      allowedIPs,
		AddressFamilies: families,
		PublicKey:       rec.PublicKey.String(),
		Active:          active,
		LastHandshakeAt: lastHandshake,
		CreatedAt:       createdAt,
		ExpiresAt:       expiresAt,
	}
}

// possiblePeerCountTotal is the number of peers the configured subnets can
// hold. It is fixed at startup, so it is read from the pools, not recomputed.
func (s *WireGuardService) possiblePeerCountTotal() (int, error) {
	if s.pool4 == nil && s.pool6 == nil {
		if err := s.initPools(); err != nil {
			return 0, err
		}
	}
	var total int
	if s.pool4 != nil {
		total += s.pool4.capacity
	}
	if s.pool6 != nil {
		total += s.pool6.capacity
	}
	return total, nil
}
