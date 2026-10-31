package wireguard

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestServerInfo(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	device := &wgtypes.Device{PublicKey: key, ListenPort: 51820}
	svc := &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	pub, port, err := svc.ServerInfo()
	if err != nil {
		t.Fatalf("ServerInfo: %v", err)
	}
	if pub != key.String() || port != 51820 {
		t.Errorf("got publicKey=%s port=%d", pub, port)
	}
}

func TestDeviceSnapshotPeerLookup(t *testing.T) {
	k1, _ := wgtypes.GenerateKey()
	k2, _ := wgtypes.GenerateKey()
	missing, _ := wgtypes.GenerateKey()
	snap := &deviceSnapshot{dev: &wgtypes.Device{Peers: []wgtypes.Peer{{PublicKey: k1, ReceiveBytes: 1}, {PublicKey: k2, ReceiveBytes: 2}}}}
	if p, ok := snap.peer(k2); !ok || p.ReceiveBytes != 2 {
		t.Fatalf("peer(k2) = %+v, %v", p, ok)
	}
	if _, ok := snap.peer(missing); ok {
		t.Fatal("unknown key must not be found")
	}
}

func TestReadyAndServerInfo(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	svc := &WireGuardService{client: fakeWGClient{device: &wgtypes.Device{PublicKey: key, ListenPort: 51820}}, deviceName: "wg0"}
	if err := svc.Ready(); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	pub, port, err := svc.ServerInfo()
	if err != nil || pub != key.String() || port != 51820 {
		t.Fatalf("ServerInfo = %q, %d, %v", pub, port, err)
	}
	// Cached after the first read: a broken device no longer matters.
	svc.client = fakeWGClient{err: errors.New("device offline")}
	if pub2, _, err := svc.ServerInfo(); err != nil || pub2 != pub {
		t.Fatalf("ServerInfo after device loss = %q, %v; want cached value", pub2, err)
	}
	if svc.Ready() == nil {
		t.Fatal("Ready must fail when the device can't be read")
	}
}

func TestServerInfoDeviceError(t *testing.T) {
	svc := &WireGuardService{
		client:     fakeWGClient{err: errors.New(testErrDeviceOffline)},
		deviceName: "wg0",
		store:      NewPeerStore(),
	}
	_, _, err := svc.ServerInfo()
	if err == nil {
		t.Fatal(msgExpectedDeviceUnavailable)
	}
}

func TestDeviceCacheSuccess(t *testing.T) {
	want := &wgtypes.Device{Name: "wg0", ListenPort: 51820}
	svc := newSvcWithCache(fakeWGClient{device: want}, time.Second)

	got, err := svc.cachedDevice()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ListenPort != want.ListenPort {
		t.Fatalf("got ListenPort %d, want %d", got.ListenPort, want.ListenPort)
	}
}

func TestDeviceCacheClientError(t *testing.T) {
	sentinel := errors.New("kernel module gone")
	svc := newSvcWithCache(fakeWGClient{err: sentinel}, time.Second)

	_, err := svc.cachedDevice()
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}

func TestDeviceCacheHit(t *testing.T) {
	client := &countingClient{dev: &wgtypes.Device{ListenPort: 51820}}
	svc := newSvcWithCache(client, time.Second)

	for i := range 5 {
		if _, err := svc.cachedDevice(); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}
	if client.calls != 1 {
		t.Fatalf("expected 1 kernel call, got %d", client.calls)
	}
}

func TestDeviceCacheMissAfterTTL(t *testing.T) {
	client := &countingClient{dev: &wgtypes.Device{}}
	svc := newSvcWithCache(client, 20*time.Millisecond)

	if _, err := svc.cachedDevice(); err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}
	time.Sleep(30 * time.Millisecond) // wait for TTL to expire
	if _, err := svc.cachedDevice(); err != nil {
		t.Fatalf("second call: unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Fatalf("expected 2 kernel calls after TTL expiry, got %d", client.calls)
	}
}

// TestDeviceCacheErrorCachedForTTL checks that a failed device read is reused
// for the cache TTL, so callers queued behind a timed-out fetch don't each
// wait for their own timeout, and that the next read after the TTL retries.
func TestDeviceCacheErrorCachedForTTL(t *testing.T) {
	sentinel := errors.New("transient error")
	calls := 0
	var client fakeWGClientFunc = func() (*wgtypes.Device, error) {
		calls++
		if calls == 1 {
			return nil, sentinel
		}
		return &wgtypes.Device{ListenPort: 1234}, nil
	}
	svc := newSvcWithCache(client, 30*time.Millisecond)

	for range 3 {
		if _, err := svc.cachedDevice(); !errors.Is(err, sentinel) {
			t.Fatalf("expected the cached sentinel, got %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("expected 1 kernel call while the error is cached, got %d", calls)
	}
	time.Sleep(40 * time.Millisecond)
	got, err := svc.cachedDevice()
	if err != nil || got.ListenPort != 1234 {
		t.Fatalf("after TTL: got %v, %v; want a fresh read", got, err)
	}
}

// TestDeviceWithTimeoutExpires verifies that deviceWithTimeout returns an error
// when the kernel call does not respond within the configured timeout.
func TestDeviceWithTimeoutExpires(t *testing.T) {
	bc := newBlockingClient()
	defer close(bc.done) // unblock the goroutine when the test ends
	svc := &WireGuardService{
		client:          bc,
		deviceName:      "wg0",
		deviceOpTimeout: 20 * time.Millisecond,
	}
	_, err := svc.deviceWithTimeout()
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, ErrDeviceTimeout) {
		t.Fatalf("expected ErrDeviceTimeout, got %v", err)
	}
}

// TestDeviceReadsStuckAreCapped checks that reads stuck in the kernel don't
// pile up: past maxConcurrentDeviceReads, new reads fail fast as busy.
func TestDeviceReadsStuckAreCapped(t *testing.T) {
	bc := newBlockingClient()
	defer close(bc.done)
	svc := &WireGuardService{client: bc, deviceName: "wg0", deviceOpTimeout: 10 * time.Millisecond}
	for range maxConcurrentDeviceReads {
		if _, err := svc.deviceWithTimeout(); !errors.Is(err, ErrDeviceTimeout) {
			t.Fatalf("expected timeout, got %v", err)
		}
	}
	start := time.Now()
	if _, err := svc.deviceWithTimeout(); !errors.Is(err, ErrDeviceBusy) {
		t.Fatalf("expected ErrDeviceBusy once reads are stuck, got %v", err)
	}
	if time.Since(start) > 5*time.Millisecond {
		t.Fatal("a busy read must fail fast, not wait for the timeout")
	}
}

// TestCreatePeerTimeoutKeepsStoreAndReconciles checks the timeout path: the
// peer is kept in the store (the kernel may still apply it), the caller gets
// ErrDeviceTimeout, a second change fails fast as busy while the first call is
// stuck, and the background reconcile puts the peer on the device afterwards.
func TestCreatePeerTimeoutKeepsStoreAndReconciles(t *testing.T) {
	bc := blockingConfigureClient{done: make(chan struct{}), device: &wgtypes.Device{}}
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		client: bc, deviceName: "wg0", subnet4: subnet4, serverIP4: net.ParseIP(ipServerTest),
		store: NewPeerStore(), deviceOpTimeout: 10 * time.Millisecond,
		reconcileSignal: make(chan struct{}, 1),
	}

	if _, err := svc.EnsurePeer(peerIDNewPeer, nil, nil); !errors.Is(err, ErrDeviceTimeout) {
		t.Fatalf("expected ErrDeviceTimeout, got %v", err)
	}
	if _, ok := svc.store.Get(peerIDNewPeer); !ok {
		t.Fatal("peer must stay in the store after a timeout")
	}
	if !svc.needsReconcile.Load() {
		t.Fatal("a timeout must schedule a reconcile")
	}
	select {
	case <-svc.reconcileSignal:
	default:
		t.Fatal("a timeout must wake the background loop")
	}

	if _, err := svc.EnsurePeer("another-peer", nil, nil); !errors.Is(err, ErrDeviceBusy) {
		t.Fatalf("expected ErrDeviceBusy while the first call is stuck, got %v", err)
	}
	if _, ok := svc.store.Get("another-peer"); ok {
		t.Fatal("a busy device must not leave the peer in the store")
	}

	close(bc.done) // the kernel call returns
	deadline := time.Now().Add(time.Second)
	for svc.configuring.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	svc.reconcileIfNeeded()
	if svc.needsReconcile.Load() {
		t.Fatal("reconcile should succeed once the device responds")
	}
}
