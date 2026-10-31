package wireguard

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// configureDevice wraps client.ConfigureDevice with a hard timeout so that a
// hung kernel module cannot block HTTP handlers indefinitely. The underlying
// syscall cannot be cancelled, so when the timeout fires the goroutine running
// the call continues in the background; the buffered channel ensures it
// eventually exits without leaking.
func (s *WireGuardService) configureDevice(cfg wgtypes.Config) error {
	if !s.configuring.CompareAndSwap(false, true) {
		return fmt.Errorf("%w: %w", ErrDevice, ErrDeviceBusy)
	}
	done := make(chan error, 1)
	go func() {
		defer s.configuring.Store(false)
		done <- s.client.ConfigureDevice(s.deviceName, cfg)
	}()
	timer := time.NewTimer(s.opTimeout())
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("%w: %w", ErrDevice, err)
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("%w: %w", ErrDevice, ErrDeviceTimeout)
	}
}

func (s *WireGuardService) opTimeout() time.Duration {
	if s.deviceOpTimeout > 0 {
		return s.deviceOpTimeout
	}
	return wgOpTimeout
}

// deviceChangeUncertain reports whether err means the device may or may not
// have applied the change (a timeout). Callers then keep the write-ahead
// state in the store instead of rolling it back, and the device is
// reconciled to the store in the background: rolling back would be wrong if
// the kernel applies the change late, for example after a rotation the client
// holding the old key would be locked out.
func (s *WireGuardService) deviceChangeUncertain(err error) bool {
	if !errors.Is(err, ErrDeviceTimeout) {
		return false
	}
	s.needsReconcile.Store(true)
	select {
	case s.reconcileSignal <- struct{}{}:
	default:
	}
	slog.Warn("wireguard device timed out; the peer store is kept and the device will be reconciled to it")
	return true
}

// reconcileIfNeeded brings the device back in line with the store after a
// timed-out change. It retries on the next call until it succeeds.
func (s *WireGuardService) reconcileIfNeeded() {
	if !s.needsReconcile.Load() {
		return
	}
	s.mu.Lock()
	err := s.reconcileStoreWithDevice()
	s.mu.Unlock()
	if err != nil {
		slog.Warn("reconcile device with peer store failed; will retry", "error", err)
		return
	}
	s.needsReconcile.Store(false)
	slog.Info("device reconciled with peer store")
}

// deviceCacheTTL is how long a device snapshot is reused. Only handshake times
// and traffic counters go stale within it; peer membership is read from the
// store. Callers poll every few seconds at most (/readyz, scrapes), so a
// shorter TTL would just mean a full netlink dump per call.
const deviceCacheTTL = 5 * time.Second

// deviceCache holds a short-lived snapshot of the WireGuard device state.
// Multiple concurrent read operations (Stats, ListPeers, GetPeer, ServerInfo)
// share one kernel round-trip per TTL window instead of each issuing their own
// netlink call.
type deviceCache struct {
	mu        sync.Mutex
	snap      *deviceSnapshot
	fetchedAt time.Time
	err       error
	errAt     time.Time
	ttl       time.Duration
}

// deviceSnapshot is one device read plus a peer index built on first use, so
// looking up a peer by key is O(1) and the index is built once per snapshot
// rather than once per request.
type deviceSnapshot struct {
	dev   *wgtypes.Device
	once  sync.Once
	byKey map[wgtypes.Key]int
}

// peer returns the device peer with the given public key.
func (d *deviceSnapshot) peer(key wgtypes.Key) (wgtypes.Peer, bool) {
	d.once.Do(func() {
		d.byKey = make(map[wgtypes.Key]int, len(d.dev.Peers))
		for i := range d.dev.Peers {
			d.byKey[d.dev.Peers[i].PublicKey] = i
		}
	})
	i, ok := d.byKey[key]
	if !ok {
		return wgtypes.Peer{}, false
	}
	return d.dev.Peers[i], true
}

func newDeviceCache(ttl time.Duration) *deviceCache {
	return &deviceCache{ttl: ttl}
}

// get returns a cached device snapshot, or fetches a fresh one via fetch when
// the cache is empty or stale.
func (c *deviceCache) get(fetch func() (*wgtypes.Device, error)) (*deviceSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.snap != nil && time.Since(c.fetchedAt) < c.ttl {
		return c.snap, nil
	}
	// A recent failure is returned as is: callers queued behind a fetch that
	// timed out must not each wait for their own timeout.
	if c.err != nil && time.Since(c.errAt) < c.ttl {
		return nil, c.err
	}
	dev, err := fetch()
	if err != nil {
		c.err, c.errAt = err, time.Now()
		return nil, err
	}
	c.err = nil
	c.snap = &deviceSnapshot{dev: dev}
	c.fetchedAt = time.Now()
	return c.snap, nil
}

// deviceWithTimeout wraps client.Device with a hard timeout so that a hung
// kernel module cannot block read operations (Stats, ListPeers, GetPeer,
// ServerInfo) indefinitely. The underlying syscall cannot be cancelled, so
// when the timeout fires the goroutine continues in the background; the
// buffered channel ensures it eventually exits without leaking.
func (s *WireGuardService) deviceWithTimeout() (*wgtypes.Device, error) {
	// A couple of concurrent reads are normal (the cache fetch and a
	// background reconcile); more means earlier calls are stuck in the kernel.
	if s.reading.Add(1) > maxConcurrentDeviceReads {
		s.reading.Add(-1)
		return nil, fmt.Errorf("read wireguard device: %w", ErrDeviceBusy)
	}
	type result struct {
		dev *wgtypes.Device
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer s.reading.Add(-1)
		dev, err := s.client.Device(s.deviceName)
		done <- result{dev, err}
	}()
	timer := time.NewTimer(s.opTimeout())
	defer timer.Stop()
	select {
	case r := <-done:
		return r.dev, r.err
	case <-timer.C:
		return nil, fmt.Errorf("read wireguard device: %w", ErrDeviceTimeout)
	}
}

const maxConcurrentDeviceReads = 2

// cachedDevice returns a recent snapshot of the WireGuard device, fetching a
// fresh one from the kernel when the cache has expired. Falls back to a direct
// call when devCache is nil (e.g. in tests that construct the service manually).
func (s *WireGuardService) cachedDevice() (*wgtypes.Device, error) {
	snap, err := s.cachedSnapshot()
	if err != nil {
		return nil, err
	}
	return snap.dev, nil
}

// cachedSnapshot is cachedDevice with the per-snapshot peer index.
func (s *WireGuardService) cachedSnapshot() (*deviceSnapshot, error) {
	if s.devCache == nil {
		dev, err := s.deviceWithTimeout()
		if err != nil {
			return nil, err
		}
		return &deviceSnapshot{dev: dev}, nil
	}
	return s.devCache.get(s.deviceWithTimeout)
}

// ServerInfo returns the server's public key and listen port. Both are fixed
// for the life of the process (wg0.conf is written once at startup), so the
// first successful read is kept and peer creation never waits on a device dump.
func (s *WireGuardService) ServerInfo() (string, int, error) {
	if info := s.serverInfo.Load(); info != nil {
		return info.publicKey, info.listenPort, nil
	}
	device, err := s.cachedDevice()
	if err != nil {
		return "", 0, err
	}
	info := &serverInfo{publicKey: device.PublicKey.String(), listenPort: device.ListenPort}
	s.serverInfo.Store(info)
	return info.publicKey, info.listenPort, nil
}

type serverInfo struct {
	publicKey  string
	listenPort int
}

// Ready reports whether the WireGuard device can be read. It backs /readyz
// and only needs the (cached) device, not the full Stats computation.
func (s *WireGuardService) Ready() error {
	_, err := s.cachedSnapshot()
	return err
}
