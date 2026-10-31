package wireguard

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestRecordAllowedIPsInSubnets(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	_, subnet6, _ := net.ParseCIDR(subnet6TestCIDR64)
	svc := &WireGuardService{
		subnet4:   subnet4,
		serverIP4: net.ParseIP(ipServerTest),
		subnet6:   subnet6,
		serverIP6: net.ParseIP(ipv6TestAddr1),
		store:     NewPeerStore(),
	}

	recIn := PeerRecord{PresharedKey: wgtypes.Key{}, AllowedIPs: []net.IPNet{ipNet(t, "10.0.0.2"), ipNet6(t, "fd00::2")}}
	if !svc.recordAllowedIPsInSubnets(recIn) {
		t.Error("expected true for IPs in both subnets")
	}

	recOut := PeerRecord{PresharedKey: wgtypes.Key{}, AllowedIPs: []net.IPNet{ipNet(t, "192.168.1.1")}}
	if svc.recordAllowedIPsInSubnets(recOut) {
		t.Error("expected false for IP outside subnets")
	}

	svc4Only := &WireGuardService{subnet4: subnet4, serverIP4: net.ParseIP(ipServerTest), store: NewPeerStore()}
	rec4 := PeerRecord{PresharedKey: wgtypes.Key{}, AllowedIPs: []net.IPNet{ipNet(t, "10.0.0.3")}}
	if !svc4Only.recordAllowedIPsInSubnets(rec4) {
		t.Error("expected true for IPv4 in subnet")
	}
}

// TestReconcileRemovesOrphanFromDevice verifies the device→store direction of
// reconcileStoreWithDevice: peers present on the device but not in the store
// are removed (recovers from a crash mid-write or manual `wg set` calls).
func TestReconcileRemovesOrphanFromDevice(t *testing.T) {
	orphanKey, _ := wgtypes.GenerateKey()
	storedKey, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()

	client := &recordingWGClient{
		device: &wgtypes.Device{
			Peers: []wgtypes.Peer{
				{PublicKey: orphanKey, AllowedIPs: []net.IPNet{ipNet(t, "10.0.0.99")}},
				{PublicKey: storedKey, AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)}},
			},
		},
	}
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client:     client,
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       peerIDTest,
		PublicKey:    storedKey,
		PresharedKey: psk,
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
	})

	if err := svc.reconcileStoreWithDevice(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Exactly one configureDevice call expected, removing the orphan.
	if len(client.configureCalls) != 1 {
		t.Fatalf("expected 1 configureDevice call, got %d", len(client.configureCalls))
	}
	peers := client.configureCalls[0].Peers
	var sawOrphanRemove bool
	for _, p := range peers {
		if p.PublicKey == orphanKey && p.Remove {
			sawOrphanRemove = true
		}
		if p.PublicKey == storedKey {
			t.Error("stored peer should not be touched by reconcile")
		}
	}
	if !sawOrphanRemove {
		t.Error("orphan peer must be marked for removal")
	}
}

func TestReconcileStoreWithDeviceDeviceError(t *testing.T) {
	svc := &WireGuardService{client: fakeWGClient{err: errors.New("device offline")}, deviceName: "wg0", store: NewPeerStore()}
	if svc.reconcileStoreWithDevice() == nil {
		t.Fatal("expected an error when the device is unavailable")
	}
}

func TestSetupSubnet6InvalidCIDR(t *testing.T) {
	if _, _, err := setupSubnet6("not-a-cidr", ""); err == nil {
		t.Fatal("expected error for invalid CIDR in setupSubnet6")
	}
}

func TestSetupSubnet4EmptyReturnsNil(t *testing.T) {
	sub, ip, err := setupSubnet4("", "")
	if err != nil || sub != nil || ip != nil {
		t.Fatalf("expected nil results for empty subnet, got sub=%v ip=%v err=%v", sub, ip, err)
	}
}

func TestSetupSubnet4ValidNoServerIP(t *testing.T) {
	sub, ip, err := setupSubnet4(subnetTestCIDR, "")
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if sub == nil || ip == nil {
		t.Fatal("expected non-nil subnet and server IP")
	}
	if ip.String() != ipServerTest {
		t.Errorf("expected default server IP %s, got %s", ipServerTest, ip.String())
	}
}

func TestSetupSubnet4InvalidCIDR(t *testing.T) {
	if _, _, err := setupSubnet4("not-a-cidr", ""); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestSetupSubnet4IPv6Rejected(t *testing.T) {
	if _, _, err := setupSubnet4(subnet6TestCIDR64, ""); err == nil {
		t.Fatal("expected error for IPv6 passed as subnet4")
	}
}

func TestSetupSubnet4ServerIPOutsideSubnet(t *testing.T) {
	if _, _, err := setupSubnet4(subnetTestCIDR, "192.168.1.1"); err == nil {
		t.Fatal("expected error for server IP outside subnet")
	}
}

func TestSetupSubnet6EmptyReturnsNil(t *testing.T) {
	sub, ip, err := setupSubnet6("", "")
	if err != nil || sub != nil || ip != nil {
		t.Fatalf("expected nil results, got sub=%v ip=%v err=%v", sub, ip, err)
	}
}

func TestSetupSubnet6ValidNoServerIP(t *testing.T) {
	sub, ip, err := setupSubnet6(testSubnet6, "")
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if sub == nil || ip == nil {
		t.Fatal("expected non-nil subnet and server IP")
	}
}

func TestSetupSubnet6IPv4Rejected(t *testing.T) {
	if _, _, err := setupSubnet6(subnetTestCIDR, ""); err == nil {
		t.Fatal("expected error for IPv4 passed as subnet6")
	}
}

func TestValidateStoredPeersInsideOK(t *testing.T) {
	svc := newValidateTestService(t)
	setTestPeer(t, svc, "inside-peer", testPeerIP4)
	if err := svc.validateStoredPeers(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// TestValidateStoredPeersOutsideRefusesToStart guards against the old
// behaviour where a subnet typo in config.yaml deleted every stored peer.
func TestValidateStoredPeersOutsideRefusesToStart(t *testing.T) {
	svc := newValidateTestService(t)
	setTestPeer(t, svc, testOutsidePeerID, "192.168.1.5/32")
	err := svc.validateStoredPeers()
	if err == nil || !strings.Contains(err.Error(), "outside the configured subnets") {
		t.Fatalf("expected an out-of-subnet error, got %v", err)
	}
	if _, ok := svc.store.Get(testOutsidePeerID); !ok {
		t.Error("peer must not be removed")
	}
}

func TestValidateStoredPeersAddressConflicts(t *testing.T) {
	t.Run("two_peers_same_ip", func(t *testing.T) {
		svc := newValidateTestService(t)
		setTestPeer(t, svc, "peer-a", testPeerIP4)
		setTestPeer(t, svc, "peer-b", testPeerIP4)
		if err := svc.validateStoredPeers(); err == nil || !strings.Contains(err.Error(), "conflict") {
			t.Fatalf("expected an address conflict error, got %v", err)
		}
	})
	t.Run("peer_holds_server_ip", func(t *testing.T) {
		svc := newValidateTestService(t)
		setTestPeer(t, svc, "peer-a", ipServerTest+"/32")
		if err := svc.validateStoredPeers(); err == nil || !strings.Contains(err.Error(), "the server") {
			t.Fatalf("expected a server address conflict error, got %v", err)
		}
	})
}

func TestReconcileStoreWithDeviceMissingPeerAdded(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	// Device has no peers; store has one. reconcile should add it.
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "missing-peer",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	})

	if err := svc.reconcileStoreWithDevice(); err != nil {
		t.Fatalf("reconcileStoreWithDevice: %v", err)
	}
}

func TestReconcileStoreWithDevicePresentPeerSkipped(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	// Device already has the peer; nothing to add.
	device := &wgtypes.Device{
		Peers: []wgtypes.Peer{{PublicKey: key}},
	}
	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "present-peer",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	})

	if err := svc.reconcileStoreWithDevice(); err != nil {
		t.Fatalf("reconcileStoreWithDevice: %v", err)
	}
}
