package wireguard

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestStatsActivePeers(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(subnetSmallTestCIDR)
	serverIP := net.ParseIP(ipServerTest)
	now := time.Now()

	device := &wgtypes.Device{
		Peers: []wgtypes.Peer{
			{LastHandshakeTime: now.Add(-1 * time.Minute)},
			{LastHandshakeTime: now.Add(-10 * time.Minute)},
		},
	}

	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		subnet4:    subnet,
		serverIP4:  serverIP,
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       peerIDTest,
		PublicKey:    wgtypes.Key{},
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
	})

	stats, err := svc.Stats()
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if stats.Peers.Active != 1 {
		t.Fatalf("expected 1 active peer, got %d", stats.Peers.Active)
	}
	if stats.Peers.Issued != 1 {
		t.Fatalf("expected 1 issued peer, got %d", stats.Peers.Issued)
	}
}

func TestGetPeerSuccess(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	device := &wgtypes.Device{
		Peers: []wgtypes.Peer{
			{PublicKey: key, ReceiveBytes: 100, TransmitBytes: 200},
		},
	}
	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       peerIDTest,
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
	})

	detail, err := svc.GetPeer(peerIDTest)
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if detail.PeerID != peerIDTest || detail.ReceiveBytes != 100 || detail.TransmitBytes != 200 {
		t.Errorf("unexpected detail: %+v", detail)
	}
}

func TestGetPeerNotFound(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	_, err := svc.GetPeer("nonexistent")
	if !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("expected ErrPeerNotFound, got %v", err)
	}
}

func TestGetPeerDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{err: errors.New("device error")},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{PeerID: peerIDTest, PublicKey: key, PresharedKey: wgtypes.Key{}, AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)}})
	_, err := svc.GetPeer(peerIDTest)
	if err == nil {
		t.Fatal("expected error when device fails")
	}
}

func TestPeerRecordToListItemWithExpiresAt(t *testing.T) {
	future := time.Now().Add(time.Hour).UTC()
	rec := PeerRecord{
		PeerID:       peerIDTest,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    &future,
	}
	item := peerRecordToListItem(rec, wgtypes.Peer{}, time.Now())
	if item.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be non-nil")
	}
	if *item.ExpiresAt == "" {
		t.Error("expected non-empty ExpiresAt string")
	}
}

func TestPossiblePeerCountTotalDualStack(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR) // /24: 254 hosts minus the server
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		subnet4: subnet4, serverIP4: net.ParseIP(ipServerTest),
		subnet6: subnet6, serverIP6: net.ParseIP(ipv6TestAddr1),
		store: NewPeerStore(),
	}
	n, err := svc.possiblePeerCountTotal()
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if n != 253+svc.pool6.capacity {
		t.Errorf("expected 253 + %d, got %d", svc.pool6.capacity, n)
	}
}

func TestPossiblePeerCountTotalSubnet6Error(t *testing.T) {
	_, subnet128, _ := net.ParseCIDR("fd00::1/128")
	svc := &WireGuardService{subnet6: subnet128, store: NewPeerStore()}
	_, err := svc.possiblePeerCountTotal()
	if err == nil {
		t.Fatal("expected error for /128 subnet6 in possiblePeerCountTotal")
	}
}

func TestPossiblePeerCountTotalIPv6Only(t *testing.T) {
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		subnet6:   subnet6,
		serverIP6: net.ParseIP(ipv6TestAddr1),
		store:     NewPeerStore(),
	}
	n, err := svc.possiblePeerCountTotal()
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if n <= 0 {
		t.Errorf("expected positive count, got %d", n)
	}
}

func TestStatsBothSubnets(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	device := &wgtypes.Device{ListenPort: 51820}
	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		subnet6:    subnet6,
		serverIP6:  net.ParseIP(ipv6TestAddr1),
		store:      NewPeerStore(),
	}
	stats, err := svc.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(stats.WireGuard.Subnets) != 2 {
		t.Errorf("expected 2 subnets, got %d: %v", len(stats.WireGuard.Subnets), stats.WireGuard.Subnets)
	}
	if len(stats.WireGuard.AddressFamilies) != 2 {
		t.Errorf("expected 2 address families, got %d", len(stats.WireGuard.AddressFamilies))
	}
}

func TestStatsDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client:     fakeWGClient{err: errors.New(testErrDeviceError)},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	_, err := svc.Stats()
	if err == nil {
		t.Fatal(msgExpectedDeviceUnavailable)
	}
}

func TestListPeersDeviceError(t *testing.T) {
	svc := &WireGuardService{
		client:     fakeWGClient{err: errors.New(testErrDeviceError)},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	_, _, err := svc.ListPeers(0, 0)
	if err == nil {
		t.Fatal(msgExpectedDeviceUnavailable)
	}
}

func TestListPeersActivePeer(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	recentHandshake := time.Now().Add(-30 * time.Second)
	device := &wgtypes.Device{
		Peers: []wgtypes.Peer{
			{PublicKey: key, LastHandshakeTime: recentHandshake},
		},
	}
	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "active-peer",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
		CreatedAt:    time.Now().UTC(),
	})

	list, _, err := svc.ListPeers(0, 0)
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(list))
	}
	if !list[0].Active {
		t.Error("peer should be active (recent handshake)")
	}
}

func TestPeerRecordToListItemActiveState(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	rec := PeerRecord{
		PeerID:       "p1",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
		CreatedAt:    time.Now().UTC(),
	}
	recentHandshake := time.Now().Add(-30 * time.Second)
	devicePeer := wgtypes.Peer{PublicKey: key, LastHandshakeTime: recentHandshake}

	item := peerRecordToListItem(rec, devicePeer, time.Now())
	if !item.Active {
		t.Error("expected peer to be active")
	}
	if item.LastHandshakeAt == nil {
		t.Error("expected non-nil LastHandshakeAt")
	}
}

func TestPeerRecordToListItemInactiveState(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	rec := PeerRecord{
		PeerID:       "p2",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
		CreatedAt:    time.Now().UTC(),
	}
	oldHandshake := time.Now().Add(-10 * time.Minute)
	devicePeer := wgtypes.Peer{PublicKey: key, LastHandshakeTime: oldHandshake}

	item := peerRecordToListItem(rec, devicePeer, time.Now())
	if item.Active {
		t.Error("expected peer to be inactive (old handshake)")
	}
	if item.LastHandshakeAt == nil {
		t.Error("expected non-nil LastHandshakeAt for old handshake")
	}
}

func TestPeerRecordToListItemNoHandshake(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	rec := PeerRecord{
		PeerID:       "p3",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	}
	item := peerRecordToListItem(rec, wgtypes.Peer{}, time.Now())
	if item.Active {
		t.Error("expected peer to be inactive (no handshake)")
	}
	if item.LastHandshakeAt != nil {
		t.Error("expected nil LastHandshakeAt when never connected")
	}
	if item.CreatedAt != "" {
		t.Error("expected empty createdAt for zero time")
	}
}

func TestPeerRecordToListItemIPv6Family(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	rec := PeerRecord{
		PeerID:       "p4",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4, "fd00::2/128"),
		CreatedAt:    time.Now().UTC(),
	}
	item := peerRecordToListItem(rec, wgtypes.Peer{}, time.Now())
	if len(item.AddressFamilies) != 2 {
		t.Errorf(msgExpectedTwoFamilies, item.AddressFamilies)
	}
}
