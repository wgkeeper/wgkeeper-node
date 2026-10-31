package wireguard

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestRunExpiredPeersCleanupExitsOnContextCancel(t *testing.T) {
	svc := newTestServiceWithSubnet(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.RunExpiredPeersCleanup(ctx, time.Minute)
		close(done)
	}()
	cancel()
	select {
	case <-done:
		// expected
	case <-time.After(2 * time.Second):
		t.Fatal("RunExpiredPeersCleanup did not exit after context cancel")
	}
}

func TestRunExpiredPeersCleanupRemovesExpiredPeer(t *testing.T) {
	svc := newTestServiceWithSubnet(t, nil)
	expiredAt := time.Now().UTC().Add(-time.Hour)
	key, _ := wgtypes.GenerateKey()
	svc.store.Set(PeerRecord{
		PeerID:       "expired-peer",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    &expiredAt,
	})

	ctx := t.Context()
	go svc.RunExpiredPeersCleanup(ctx, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)

	list, _, err := svc.ListPeers(0, 0)
	if err != nil {
		t.Fatalf(msgListPeersFmt, err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 peers after cleanup, got %d", len(list))
	}
}

func TestRunExpiredPeersCleanupKeepsPermanentPeer(t *testing.T) {
	svc := newTestServiceWithSubnet(t, nil)
	key, _ := wgtypes.GenerateKey()
	svc.store.Set(PeerRecord{
		PeerID:       "permanent-peer",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    nil, // permanent
	})

	svc.runCleanupSafe()
	time.Sleep(10 * time.Millisecond)

	list, _, err := svc.ListPeers(0, 0)
	if err != nil {
		t.Fatalf(msgListPeersFmt, err)
	}
	if len(list) != 1 || list[0].PeerID != "permanent-peer" {
		t.Errorf("expected 1 permanent peer to remain, got %v", list)
	}
}

func TestCleanupExpiredPeersNotYetExpired(t *testing.T) {
	svc := newTestServiceWithSubnet(t, nil)
	future := time.Now().UTC().Add(time.Hour)
	key, _ := wgtypes.GenerateKey()
	svc.store.Set(PeerRecord{
		PeerID:       "not-yet-expired",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    &future,
	})
	svc.runCleanupSafe()

	list, _, err := svc.ListPeers(0, 0)
	if err != nil {
		t.Fatalf(msgListPeersFmt, err)
	}
	if len(list) != 1 {
		t.Errorf("peer with future ExpiresAt should remain, got %d peers", len(list))
	}
}

func TestCleanupExpiredPeersDeletePeerError(t *testing.T) {
	svc := newTestServiceWithSubnet(t, errors.New("device busy"))
	expiredAt := time.Now().UTC().Add(-time.Hour)
	key, _ := wgtypes.GenerateKey()
	svc.store.Set(PeerRecord{
		PeerID:       "expired-fail",
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    &expiredAt,
	})
	svc.runCleanupSafe()
	list, _, err := svc.ListPeers(0, 0)
	if err != nil {
		t.Fatalf(msgListPeersFmt, err)
	}
	if len(list) != 1 {
		t.Errorf("peer should remain when DeletePeer fails, got %d peers", len(list))
	}
}

func TestRunCleanupSafePanicRecovery(t *testing.T) {
	// nil store will cause a panic inside cleanupExpiredPeers; runCleanupSafe must recover it
	svc := &WireGuardService{store: nil}
	// Should not panic
	svc.runCleanupSafe()
}

// TestCleanupDeviceErrorRestoresRecords checks that expiry cleanup is
// write-ahead too: records deleted from bbolt are put back when the device
// call fails, so the peers are retried on the next pass instead of lost.
func TestCleanupDeviceErrorRestoresRecords(t *testing.T) {
	svc, record, path := newPersistedTestService(t, errors.New("device busy"))
	past := time.Now().Add(-time.Minute).UTC()
	record.ExpiresAt = &past
	svc.store.Set(record)

	if _, err := svc.doCleanupBatch([]string{peerIDTest}, time.Now().UTC()); err == nil {
		t.Fatal("expected error from device, got nil")
	}
	if _, ok := svc.store.Get(peerIDTest); !ok {
		t.Error("peer should remain in memory when device removal fails")
	}
	if !persistedRecord(t, svc, path, peerIDTest) {
		t.Error("bbolt record should be restored when device removal fails")
	}
}

func TestCleanupExpiredPeerReleasesIP(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	expiredAt := time.Now().UTC().Add(-time.Hour)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:     "expiring",
		PublicKey:  key,
		AllowedIPs: []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  &expiredAt,
	})
	markIPUsed(t, svc, ipPeerTest)

	svc.cleanupExpiredPeers()

	if ipInUse(t, svc, ipPeerTest) {
		t.Error("expected IP to be released after expiry cleanup")
	}
}

// TestCleanupBatchExtended verifies that doCleanupBatch skips a peer whose expiry
// was extended between the ForEach snapshot and lock acquisition (simulated by
// storing a future ExpiresAt before calling directly).
func TestCleanupBatchExtended(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	future := time.Now().UTC().Add(time.Hour)
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "ext-peer",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    &future, // extended: ExpiresAt is in the future
	})

	deleted, err := svc.doCleanupBatch([]string{"ext-peer"}, time.Now().UTC())
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(deleted) != 0 {
		t.Fatalf("expected no deletions for peer whose expiry was extended, got %v", deleted)
	}
}

// TestCleanupBatchMadePermanent verifies that doCleanupBatch skips a peer that
// was made permanent (ExpiresAt set to nil) between ForEach snapshot and lock acquisition.
func TestCleanupBatchMadePermanent(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "perm-peer",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    nil, // permanent peer
	})

	deleted, err := svc.doCleanupBatch([]string{"perm-peer"}, time.Now().UTC())
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(deleted) != 0 {
		t.Fatalf("expected no deletions for permanent peer, got %v", deleted)
	}
}

// TestCleanupBatchConfigureDeviceError verifies that doCleanupBatch returns an
// error and leaves the store intact when configureDevice fails.
func TestCleanupBatchConfigureDeviceError(t *testing.T) {
	past := time.Now().UTC().Add(-time.Hour)
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New(testErrDeviceBusyMessage)},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "expired",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    &past,
	})

	deleted, err := svc.doCleanupBatch([]string{"expired"}, time.Now().UTC())
	if err == nil {
		t.Fatal("expected error from configureDevice, got nil")
	}
	if len(deleted) != 0 {
		t.Fatalf("expected no deletions on error, got %v", deleted)
	}
	if _, ok := svc.store.Get("expired"); !ok {
		t.Fatal("peer should remain in store when configureDevice fails")
	}
}

// TestCleanupExpiredPeersLogsBatchError verifies that cleanupExpiredPeers logs
// the doCleanupBatch error and returns cleanly (no panic) when configureDevice fails.
func TestCleanupExpiredPeersLogsBatchError(t *testing.T) {
	past := time.Now().UTC().Add(-time.Hour)
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: errors.New(testErrDeviceBusyMessage)},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	svc.store.Set(PeerRecord{
		PeerID:       "expired",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    &past,
	})
	// Must not panic; error is logged internally.
	svc.cleanupExpiredPeers()
	if _, ok := svc.store.Get("expired"); !ok {
		t.Fatal("peer should remain in store when batch delete fails")
	}
}
