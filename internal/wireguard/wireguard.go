package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wgkeeper/wgkeeper-node/internal/config"
	"github.com/wgkeeper/wgkeeper-node/internal/version"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	FamilyIPv4 = "IPv4"
	FamilyIPv6 = "IPv6"

	errSavePeerStoreFmt = "%w: %w" // ErrPeerStore, cause
)

var (
	ErrPeerNotFound             = errors.New("peer not found")
	ErrNoAvailableIP            = errors.New("no available ip addresses")
	ErrUnsupportedAddressFamily = errors.New("requested address family is not supported by this node")
	// ErrInvalidAddressFamily marks a malformed addressFamilies list: an
	// unknown value or a duplicate. It is a client error, unlike
	// ErrUnsupportedAddressFamily's valid-but-unavailable family.
	ErrInvalidAddressFamily = errors.New("invalid address family")
	// ErrPeerStore wraps failures to write the bbolt peer store.
	ErrPeerStore = errors.New("save peer store")
	// ErrDevice wraps failures to change the WireGuard device.
	ErrDevice = errors.New("configure wireguard device")
	// ErrPeerExpired is returned when rotating a peer whose expiry has passed
	// without giving it a new one: the rotation would succeed and the cleanup
	// loop would delete the peer moments later.
	ErrPeerExpired = errors.New("peer has expired; pass a future expiresAt to renew it")
)

const (
	activePeerWindow = 2 * time.Minute
	// wgOpTimeout is the maximum time allowed for a single WireGuard kernel
	// operation (ConfigureDevice). If the kernel module becomes unresponsive,
	// this prevents HTTP handlers from hanging indefinitely.
	wgOpTimeout = 10 * time.Second
	// HandshakeStaleThreshold defines the cutoff for "stale" peers reported
	// via WireGuardSnapshot. Distinct from activePeerWindow on purpose: stale
	// is a looser signal for monitoring (peer is degraded but maybe alive),
	// active is a tighter "currently passing traffic" definition for /stats.
	HandshakeStaleThreshold = 5 * time.Minute
)

var serverStart = time.Now()

type PeerInfo struct {
	PeerID          string
	PublicKey       string
	PrivateKey      string
	PresharedKey    string
	AllowedIPs      []string // one per family (e.g. ["10.0.0.2/32", "fd00::2/128"])
	AddressFamilies []string // e.g. ["IPv4", "IPv6"] — what this peer has
	// Rotated is true when EnsurePeer rotated keys for an existing peer rather
	// than creating a fresh one. Used by HTTP handlers for audit logging only;
	// not surfaced in JSON responses.
	Rotated bool
}

// RollbackObserver receives notifications about write-ahead persist rollback
// events. The wireguard package depends on this interface only to keep the
// metrics package out of service code; in production it is implemented by
// *metrics.Metrics. nil observer means metrics are disabled — no allocations,
// no calls.
type RollbackObserver interface {
	// OnPersistRollback fires when configureDevice failed and the bbolt write
	// was rolled back successfully. op is "create", "rotate", "delete" or "expire".
	OnPersistRollback(op string)
	// OnPersistRollbackFailed fires when the rollback itself errored — bbolt
	// holds a record that startup reconcile will install on the device next
	// run. This is the alert-the-on-call path.
	OnPersistRollbackFailed()
	// OnPeersExpired fires after the cleanup loop removed n expired peers.
	OnPeersExpired(n int)
}

const (
	rollbackOpCreate = "create"
	rollbackOpRotate = "rotate"
	rollbackOpDelete = "delete"
	rollbackOpExpire = "expire"
)

type WireGuardService struct {
	client      wgClient
	deviceName  string
	subnet4     *net.IPNet
	serverIP4   net.IP
	subnet6     *net.IPNet
	serverIP6   net.IP
	store       *PeerStore
	persistPath string // bbolt file the store is persisted to; empty only in tests
	// rollbackObs receives persist-rollback notifications when set. May be nil
	// (metrics disabled). All call sites must nil-check before invoking.
	rollbackObs RollbackObserver
	// mu serializes operations that modify WireGuard device and peer store together
	mu sync.Mutex
	// pool4/pool6 track which peer addresses are taken and hand out free ones.
	// They mirror the store plus the server addresses. nil when the family is
	// not configured. Accessed only under mu.
	pool4 *ipPool
	pool6 *ipPool
	// devCache caches the result of client.Device for a short TTL so that
	// concurrent read operations (Stats, ListPeers, GetPeer, ServerInfo) share
	// a single kernel round-trip instead of each issuing their own netlink call.
	devCache *deviceCache
	// serverInfo caches the server public key and listen port after the first
	// successful device read; see ServerInfo.
	serverInfo atomic.Pointer[serverInfo]
	// deviceOpTimeout overrides wgOpTimeout for device read operations.
	// Zero means use wgOpTimeout. Exposed for tests only.
	deviceOpTimeout time.Duration
}

type wgClient interface {
	Device(string) (*wgtypes.Device, error)
	ConfigureDevice(string, wgtypes.Config) error
}

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

func NewWireGuardService(cfg config.Config) (*WireGuardService, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	subnet4, serverIP4, err := setupSubnet4(cfg.WGSubnet, cfg.WGServerIP)
	if err != nil {
		return nil, err
	}
	subnet6, serverIP6, err := setupSubnet6(cfg.WGSubnet6, cfg.WGServerIP6)
	if err != nil {
		return nil, err
	}
	svc := &WireGuardService{
		client:      client,
		deviceName:  cfg.WGInterface,
		subnet4:     subnet4,
		serverIP4:   serverIP4,
		subnet6:     subnet6,
		serverIP6:   serverIP6,
		store:       NewPeerStore(),
		persistPath: cfg.PeerStoreFile,
		devCache:    newDeviceCache(deviceCacheTTL),
	}
	if err := initPersistStore(svc); err != nil {
		return nil, errors.Join(err, svc.store.Close())
	}
	if err := svc.initPools(); err != nil {
		return nil, errors.Join(err, svc.store.Close())
	}
	return svc, nil
}

func setupSubnet4(subnet, serverIP string) (*net.IPNet, net.IP, error) {
	if subnet == "" {
		return nil, nil, nil
	}
	_, sub, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid WG_SUBNET: %w", err)
	}
	if sub.IP.To4() == nil {
		return nil, nil, errors.New("wireguard.subnet must be IPv4")
	}
	ip, err := resolveServerIP4(sub, serverIP)
	if err != nil {
		return nil, nil, err
	}
	return sub, ip, nil
}

func setupSubnet6(subnet6, serverIP6 string) (*net.IPNet, net.IP, error) {
	if subnet6 == "" {
		return nil, nil, nil
	}
	_, sub, err := net.ParseCIDR(subnet6)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid WG_SUBNET6: %w", err)
	}
	if sub.IP.To4() != nil {
		return nil, nil, errors.New("wireguard.subnet6 must be IPv6")
	}
	ip, err := resolveServerIP6(sub, serverIP6)
	if err != nil {
		return nil, nil, err
	}
	return sub, ip, nil
}

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
				"publicKey", device.Peers[i].PublicKey.String())
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

// Close releases resources held by the service, including the peer store DB.
func (s *WireGuardService) Close() error {
	return s.store.Close()
}

// SetRollbackObserver attaches a RollbackObserver to the service. Call before
// the service handles requests. Not safe to swap under concurrent traffic.
func (s *WireGuardService) SetRollbackObserver(obs RollbackObserver) {
	s.rollbackObs = obs
}

// notifyRollback is a nil-safe wrapper used in createPeer/rotatePeer.
func (s *WireGuardService) notifyRollback(op string, rollbackErr error) {
	if s.rollbackObs == nil {
		return
	}
	if rollbackErr != nil {
		s.rollbackObs.OnPersistRollbackFailed()
		return
	}
	s.rollbackObs.OnPersistRollback(op)
}

// configureDevice wraps client.ConfigureDevice with a hard timeout so that a
// hung kernel module cannot block HTTP handlers indefinitely. The underlying
// syscall cannot be cancelled, so when the timeout fires the goroutine running
// the call continues in the background; the buffered channel ensures it
// eventually exits without leaking.
func (s *WireGuardService) configureDevice(cfg wgtypes.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), wgOpTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.client.ConfigureDevice(s.deviceName, cfg) }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("%w: %w", ErrDevice, err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", ErrDevice, ctx.Err())
	}
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
	dev, err := fetch()
	if err != nil {
		return nil, err
	}
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
	timeout := s.deviceOpTimeout
	if timeout <= 0 {
		timeout = wgOpTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	type result struct {
		dev *wgtypes.Device
		err error
	}
	done := make(chan result, 1)
	go func() {
		dev, err := s.client.Device(s.deviceName)
		done <- result{dev, err}
	}()
	select {
	case r := <-done:
		return r.dev, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf("read wireguard device: %w", ctx.Err())
	}
}

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

// NodeAddressFamilies returns the address families this node supports (e.g. ["IPv4", "IPv6"]).
func (s *WireGuardService) NodeAddressFamilies() []string {
	var out []string
	if s.subnet4 != nil {
		out = append(out, FamilyIPv4)
	}
	if s.subnet6 != nil {
		out = append(out, FamilyIPv6)
	}
	return out
}

// ValidateAddressFamilies checks that requested families are supported by the node.
// If requested is nil or empty, returns node's families (default = all). No duplicates allowed.
func (s *WireGuardService) ValidateAddressFamilies(requested []string) ([]string, error) {
	nodeFamilies := s.NodeAddressFamilies()
	if len(requested) == 0 {
		return nodeFamilies, nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, f := range requested {
		if f != FamilyIPv4 && f != FamilyIPv6 {
			return nil, fmt.Errorf("%w: addressFamilies may only contain %q and %q", ErrInvalidAddressFamily, FamilyIPv4, FamilyIPv6)
		}
		if seen[f] {
			return nil, fmt.Errorf("%w: duplicate %q", ErrInvalidAddressFamily, f)
		}
		seen[f] = true
		if !slices.Contains(nodeFamilies, f) {
			return nil, ErrUnsupportedAddressFamily
		}
		out = append(out, f)
	}
	return out, nil
}

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
		// Rollback persist (best-effort). On rollback failure the peer remains
		// in bbolt as an orphan; startup reconcile will install it on the
		// device next time and it becomes a normal (unused) peer the operator
		// can delete via the API.
		rbErr := s.store.PersistDeleteBatch(peerID)
		if rbErr != nil {
			slog.Error("rollback persist after configureDevice failure",
				"peerId", peerID, "rollback_error", rbErr, "device_error", err)
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
		rbErr := s.store.PersistPut(record)
		if rbErr != nil {
			slog.Error("rollback persist after delete failure",
				"peerId", peerID, "rollback_error", rbErr, "device_error", err)
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
		// Rollback persist to the old record. Best-effort: on rollback failure
		// bbolt holds the new key while the device still has the old one.
		// Startup reconcile will then install the new key — orphaning the old
		// peer on the device is impossible because we did not configureDevice.
		rbErr := s.store.PersistPut(record)
		if rbErr != nil {
			slog.Error("rollback persist after rotation failure",
				"peerId", peerID, "rollback_error", rbErr, "device_error", err)
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

func resolveServerIP4(subnet *net.IPNet, serverIP string) (net.IP, error) {
	return resolveServerIP(subnet, serverIP, "wireguard.server_ip", "wireguard.subnet", true)
}

func resolveServerIP6(subnet *net.IPNet, serverIP string) (net.IP, error) {
	return resolveServerIP(subnet, serverIP, "wireguard.server_ip6", "wireguard.subnet6", false)
}

// resolveServerIP returns the configured server address, or the first host of
// the subnet when none is configured.
func resolveServerIP(subnet *net.IPNet, serverIP, ipField, subnetField string, want4 bool) (net.IP, error) {
	prefix, err := prefixFromIPNet(subnet)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", subnetField, err)
	}
	if prefix.Addr().Is4() != want4 {
		return nil, fmt.Errorf("%s has the wrong address family", subnetField)
	}
	first, _, err := hostRange(prefix)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", subnetField, err)
	}
	if serverIP == "" {
		return net.IP(first.AsSlice()), nil
	}
	a, err := netip.ParseAddr(serverIP)
	if err != nil || a.Is4() != want4 || a.Is4In6() {
		family := "IPv6"
		if want4 {
			family = "IPv4"
		}
		return nil, fmt.Errorf("%s must be a valid %s address", ipField, family)
	}
	if !prefix.Contains(a) {
		return nil, fmt.Errorf("%s must be inside %s", ipField, subnetField)
	}
	return net.IP(a.AsSlice()), nil
}

func keepaliveInterval() *time.Duration {
	interval := 25 * time.Second
	return &interval
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
