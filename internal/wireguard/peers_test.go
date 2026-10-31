package wireguard

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestAllocateIPSkipsUsed(t *testing.T) {
	svc := newTestServiceWithSubnet29(t, &wgtypes.Device{})
	svc.store.Set(PeerRecord{
		PeerID:       peerIDTest,
		PublicKey:    wgtypes.Key{},
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
	})
	svc.store.Set(PeerRecord{
		PeerID:       "peer-2",
		PublicKey:    wgtypes.Key{1},
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, "10.0.0.3")},
	})

	ips, err := svc.allocateIPs([]string{FamilyIPv4})
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(ips) != 1 || ips[0].IP.String() != "10.0.0.4" {
		t.Fatalf("expected [10.0.0.4/32], got %v", ips)
	}
}

func TestAllocateIPNoAvailable(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/30")
	serverIP := net.ParseIP(ipServerTest)

	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
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

	_, err := svc.allocateIPs([]string{FamilyIPv4})
	if !errors.Is(err, ErrNoAvailableIP) {
		t.Fatalf("expected ErrNoAvailableIP, got %v", err)
	}
}

func TestEnsurePeerNewPeer(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetSmallTestCIDR)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	info, err := svc.EnsurePeer(peerIDNewPeer, nil, nil)
	if err != nil {
		t.Fatalf("EnsurePeer: %v", err)
	}
	if info.PeerID != peerIDNewPeer || info.PublicKey == "" || info.PrivateKey == "" {
		t.Errorf("unexpected PeerInfo: %+v", info)
	}
	if len(info.AllowedIPs) != 1 || !strings.Contains(info.AllowedIPs[0], "10.0.0.") {
		t.Errorf("unexpected AllowedIPs: %v", info.AllowedIPs)
	}
	_, ok := svc.store.Get(peerIDNewPeer)
	if !ok {
		t.Error("peer should be in store")
	}
}

func TestEnsurePeerNoAvailableIP(t *testing.T) {
	// /30 gives only 2 usable IPs (.1=server, .2=only peer slot)
	_, subnet, _ := net.ParseCIDR("10.0.0.0/30")
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	// occupy the only usable IP
	svc.store.Set(PeerRecord{
		PeerID:       peerIDTest,
		PublicKey:    wgtypes.Key{},
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
	})

	_, err := svc.EnsurePeer("new-peer-no-ip", nil, nil)
	if !errors.Is(err, ErrNoAvailableIP) {
		t.Fatalf("expected ErrNoAvailableIP, got %v", err)
	}
}

func TestEnsurePeerNewPeerSavePersistError(t *testing.T) {
	dir := t.TempDir()
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	openAndBreakDB(t, svc.store, dir+peersDBFile)
	_, err := svc.EnsurePeer(peerIDNewPeer, nil, nil)
	if err == nil {
		t.Fatal("expected error when persist fails for new peer")
	}
	if !strings.Contains(err.Error(), savePeerStoreSubstr) {
		t.Errorf(msgSavePeerStoreErr, err)
	}
}

func TestDeletePeerSavePersistError(t *testing.T) {
	dir := t.TempDir()
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	// Open and break DB first; then set peer so it's in memory for DeletePeer.
	openAndBreakDB(t, svc.store, dir+peersDBFile)
	svc.store.Set(PeerRecord{
		PeerID:       peerIDTest,
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
	})
	_, err := svc.DeletePeer(peerIDTest)
	if err == nil {
		t.Fatal("expected error when persist fails after delete")
	}
	if !strings.Contains(err.Error(), savePeerStoreSubstr) {
		t.Errorf(msgSavePeerStoreErr, err)
	}
}

func TestEnsurePeerRotateSavePersistError(t *testing.T) {
	dir := t.TempDir()
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	// Open and break DB first; then set peer so it's in memory for rotate path.
	openAndBreakDB(t, svc.store, dir+peersDBFile)
	svc.store.Set(PeerRecord{
		PeerID:       peerIDTest,
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
	})
	_, err := svc.EnsurePeer(peerIDTest, nil, nil)
	if err == nil {
		t.Fatal("expected error when persist fails during rotation")
	}
	if !strings.Contains(err.Error(), savePeerStoreSubstr) {
		t.Errorf(msgSavePeerStoreErr, err)
	}
}

func TestDeletePeerRemovesEverywhere(t *testing.T) {
	svc, _, path := newPersistedTestService(t, nil)

	if _, err := svc.DeletePeer(peerIDTest); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	if _, ok := svc.store.Get(peerIDTest); ok {
		t.Error("peer should be removed from memory")
	}
	if ipInUse(t, svc, ipPeerTest) {
		t.Error("IP should be released")
	}
	if persistedRecord(t, svc, path, peerIDTest) {
		t.Error("peer should be removed from bbolt")
	}
}

// TestDeletePeerDeviceErrorRestoresRecord checks the write-ahead rollback: the
// bbolt delete happens first and is undone when the device call fails, so a
// failed delete leaves the peer intact everywhere and a retry can succeed.
func TestDeletePeerDeviceErrorRestoresRecord(t *testing.T) {
	svc, _, path := newPersistedTestService(t, errors.New("device busy"))

	if _, err := svc.DeletePeer(peerIDTest); err == nil {
		t.Fatal("expected error from device, got nil")
	}
	if _, ok := svc.store.Get(peerIDTest); !ok {
		t.Error("peer should remain in memory when device removal fails")
	}
	if !ipInUse(t, svc, ipPeerTest) {
		t.Error("IP should stay allocated when device removal fails")
	}
	if !persistedRecord(t, svc, path, peerIDTest) {
		t.Error("bbolt record should be restored when device removal fails")
	}
}

func TestEnsurePeerRotateExpired(t *testing.T) {
	past := time.Now().Add(-time.Minute).UTC()
	future := time.Now().Add(time.Hour).UTC()

	t.Run("without_new_expiry_is_rejected", func(t *testing.T) {
		svc, record, _ := newPersistedTestService(t, nil)
		record.ExpiresAt = &past
		svc.store.Set(record)
		if _, err := svc.EnsurePeer(peerIDTest, nil, nil); !errors.Is(err, ErrPeerExpired) {
			t.Fatalf("expected ErrPeerExpired, got %v", err)
		}
	})

	t.Run("with_future_expiry_renews", func(t *testing.T) {
		svc, record, _ := newPersistedTestService(t, nil)
		record.ExpiresAt = &past
		svc.store.Set(record)
		info, err := svc.EnsurePeer(peerIDTest, &future, nil)
		if err != nil || !info.Rotated {
			t.Fatalf("expected a successful rotation, got %+v, %v", info, err)
		}
		got, _ := svc.store.Get(peerIDTest)
		if got.ExpiresAt == nil || !got.ExpiresAt.Equal(future) {
			t.Errorf("expiry should be renewed, got %v", got.ExpiresAt)
		}
	})
}

func TestEnsurePeerDuplicateRotates(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetSmallTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{Peers: []wgtypes.Peer{{PublicKey: key, AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)}}}}},
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
	info, err := svc.EnsurePeer(peerIDTest, nil, nil)
	if err != nil {
		t.Fatalf("EnsurePeer rotate: %v", err)
	}
	if info.PeerID != peerIDTest {
		t.Errorf("PeerID: got %s", info.PeerID)
	}
	rec, ok := svc.store.Get(peerIDTest)
	if !ok {
		t.Fatal("peer should still be in store")
	}
	if rec.PublicKey == key {
		t.Error("public key should have been rotated")
	}
}

// TestEnsurePeerCreateRollbacksOnDeviceFailure verifies the write-ahead order:
// on a new peer, PersistPut runs before configureDevice; if configureDevice
// fails the bbolt record is rolled back and the IP is released so a retry can
// allocate the same address.
// TestEnsurePeerRotateRollbacksOnDeviceFailure verifies that a failed
// configureDevice during rotation rolls bbolt back to the original record so
// a restart restores the still-working old key on the device.
func TestEnsurePeerRotateRollbacksOnDeviceFailure(t *testing.T) {
	dir := t.TempDir()
	path := dir + peersDBFile
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	originalKey, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()

	// Open the store, persist the original record, then attach the configure-failing client.
	store := NewPeerStore()
	if err := store.OpenFile(path); err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	rec := PeerRecord{
		PeerID:       peerIDTest,
		PublicKey:    originalKey,
		PresharedKey: psk,
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
	}
	store.Set(rec)
	if err := store.PersistPut(rec); err != nil {
		t.Fatalf("PersistPut original: %v", err)
	}

	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New("device busy")},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      store,
	}

	if _, err := svc.EnsurePeer(peerIDTest, nil, nil); err == nil {
		t.Fatal("expected device error during rotation")
	}

	// bbolt must hold the ORIGINAL key after rollback (not the new one).
	store.Close()
	store2 := NewPeerStore()
	if err := store2.OpenFile(path); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store2.Close()
	got, ok := store2.Get(peerIDTest)
	if !ok {
		t.Fatal("peer must remain in bbolt after failed rotation")
	}
	if got.PublicKey != originalKey {
		t.Error("bbolt must hold original key after rotation rollback, got new key")
	}
}

func TestAllocateIPReusesFreedAddress(t *testing.T) {
	svc := newTestServiceWithSubnet29(t, &wgtypes.Device{})
	ips1, err := svc.allocateIPs([]string{FamilyIPv4})
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	svc.releaseAllocatedIPs(ips1)
	ips2, err := svc.allocateIPs([]string{FamilyIPv4})
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if !ips2[0].IP.Equal(ips1[0].IP) {
		t.Errorf("expected freed IP %s to be reused, got %s", ips1[0].IP, ips2[0].IP)
	}
}

func TestEnsurePeerCreateRollbacksOnDeviceFailure(t *testing.T) {
	path := t.TempDir() + peersDBFile
	_, subnet4, _ := net.ParseCIDR("10.0.0.0/30") // only 1 usable IP
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New("device busy")},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	if err := svc.store.OpenFile(path); err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := svc.EnsurePeer(peerIDNewPeer, nil, nil); err == nil {
		t.Fatal("expected device error from EnsurePeer")
	}
	if _, ok := svc.store.Get(peerIDNewPeer); ok {
		t.Error("peer must not remain in memory after configureDevice failure")
	}
	if ipInUse(t, svc, ipPeerTest) {
		t.Error("IP must be released after rollback, or a retry would get 409")
	}
	if persistedRecord(t, svc, path, peerIDNewPeer) {
		t.Error("peer must not be persisted after configureDevice failure")
	}
}

func TestRotatePeerIPv6Family(t *testing.T) {
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet6:    subnet6,
		serverIP6:  net.ParseIP(ipv6TestAddr1),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{PeerID: "ipv6-peer", PublicKey: key, AllowedIPs: mustParseCIDRs(t, "fd00::2/128")})
	info, err := svc.EnsurePeer("ipv6-peer", nil, nil)
	if err != nil {
		t.Fatalf("EnsurePeer IPv6 rotate: %v", err)
	}
	if len(info.AddressFamilies) != 1 || info.AddressFamilies[0] != FamilyIPv6 {
		t.Errorf("expected [IPv6] families, got %v", info.AddressFamilies)
	}
}

func TestDeletePeerNotFound(t *testing.T) {
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	_, err := svc.DeletePeer("nonexistent")
	if !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("expected ErrPeerNotFound, got %v", err)
	}
}

func TestEnsurePeerInvalidAddressFamily(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	_, err := svc.EnsurePeer("peer-bad-family", nil, []string{"InvalidFamily"})
	if err == nil {
		t.Fatal("expected error for invalid address family")
	}
}

func TestEnsurePeerConfigureDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New(testErrDeviceBusyMessage)},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	_, err := svc.EnsurePeer("brand-new-peer", nil, nil)
	if err == nil {
		t.Fatal("expected error when ConfigureDevice fails for new peer")
	}
}

func TestAllocateIPsIPv6Only(t *testing.T) {
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet6:    subnet6,
		serverIP6:  net.ParseIP(ipv6TestAddr1),
		store:      NewPeerStore(),
	}
	ips, err := svc.allocateIPs([]string{FamilyIPv6})
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
	if ips[0].IP.To4() != nil {
		t.Error("expected IPv6 address, got IPv4")
	}
}

func TestAllocateIPsDualStack(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		subnet6:    subnet6,
		serverIP6:  net.ParseIP(ipv6TestAddr1),
		store:      NewPeerStore(),
	}
	ips, err := svc.allocateIPs([]string{FamilyIPv4, FamilyIPv6})
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs (one per family), got %d", len(ips))
	}
}

func TestEnsurePeerRotateDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New(testErrDeviceBusyMessage)},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "rotate-fail",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	})

	_, err := svc.EnsurePeer("rotate-fail", nil, nil)
	if err == nil {
		t.Fatal("expected error when ConfigureDevice fails during rotation")
	}
}

func TestEnsurePeerRotateUpdatesExpiresAt(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       testExpiryPeerID,
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	})

	future := time.Now().UTC().Add(time.Hour)
	_, err := svc.EnsurePeer(testExpiryPeerID, &future, nil)
	if err != nil {
		t.Fatalf("EnsurePeer: %v", err)
	}
	rec, _ := svc.store.Get(testExpiryPeerID)
	if rec.ExpiresAt == nil || !rec.ExpiresAt.Equal(future) {
		t.Errorf("expected expiresAt to be updated to %v, got %v", future, rec.ExpiresAt)
	}
}

func TestDeletePeerDeviceError(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New(testErrDeviceBusyMessage)},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       testDelFailPeerID,
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   mustParseCIDRs(t, testPeerIP4),
	})

	if _, err := svc.DeletePeer(testDelFailPeerID); err == nil {
		t.Fatal("expected error when ConfigureDevice fails")
	}
	// Peer should still be in store since device removal failed
	if _, ok := svc.store.Get(testDelFailPeerID); !ok {
		t.Error("peer should remain in store when device removal fails")
	}
}

// TestEnsurePeerDualStackIPv6ExhaustionReleasesIPv4 guards against a regression
// where a dual-stack create that succeeds on IPv4 but fails on IPv6 (exhausted
// pool) leaks the already-reserved IPv4 into usedIPs. A failed create must
// reserve nothing.
func TestEnsurePeerDualStackIPv6ExhaustionReleasesIPv4(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR("10.0.0.0/28") // .1 .. .14 usable
	_, subnet6, _ := net.ParseCIDR("fd00::/126")  // fd00::1, fd00::2 usable (2 total)
	svc := &WireGuardService{
		client:     FakeClient{},
		deviceName: "wg0",
		subnet4:    subnet4,
		subnet6:    subnet6,
		store:      NewPeerStore(),
	}
	both := []string{FamilyIPv4, FamilyIPv6}

	// Consume both IPv6 addresses with two dual-stack peers.
	if _, err := svc.EnsurePeer("11111111-1111-4111-8111-111111111111", nil, both); err != nil {
		t.Fatalf("peer A create: %v", err)
	}
	if _, err := svc.EnsurePeer("22222222-2222-4222-8222-222222222222", nil, both); err != nil {
		t.Fatalf("peer B create: %v", err)
	}

	usedIPv4Before := countUsedIPv4(svc)

	// IPv4 free, IPv6 exhausted → must fail and reserve nothing.
	if _, err := svc.EnsurePeer("33333333-3333-4333-8333-333333333333", nil, both); !errors.Is(err, ErrNoAvailableIP) {
		t.Fatalf("expected ErrNoAvailableIP, got %v", err)
	}

	if got := countUsedIPv4(svc); got != usedIPv4Before {
		t.Errorf("failed dual-stack create leaked an IPv4: usedIPv4 %d -> %d (peers=%d)",
			usedIPv4Before, got, svc.store.Len())
	}
}

func TestAppendIfNotPresent(t *testing.T) {
	slice := []string{"a", "b"}
	got := appendIfNotPresent(slice, "c")
	if len(got) != 3 || got[2] != "c" {
		t.Errorf("expected [a b c], got %v", got)
	}
	got = appendIfNotPresent(slice, "a")
	if len(got) != 2 {
		t.Errorf("should not duplicate a, got %v", got)
	}
}
