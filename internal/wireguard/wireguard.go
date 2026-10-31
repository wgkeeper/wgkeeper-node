package wireguard

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wgkeeper/wgkeeper-node/internal/config"

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
	// ErrDeviceTimeout means a device call did not return in time. The kernel
	// may still apply it, so the change is kept in the peer store and the
	// device is reconciled to the store in the background.
	ErrDeviceTimeout = errors.New("wireguard device did not respond in time")
	// ErrDeviceBusy means an earlier device call is still stuck in the kernel;
	// no new call was made, so nothing changed.
	ErrDeviceBusy = errors.New("an earlier wireguard device call has not returned yet")
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
	// deviceOpTimeout overrides wgOpTimeout for device calls. Zero means use
	// wgOpTimeout. Exposed for tests only.
	deviceOpTimeout time.Duration
	// configuring is set while a ConfigureDevice call runs, including one that
	// timed out and is still stuck in the kernel; reading counts device reads
	// the same way. They stop a hung netlink from piling up goroutines.
	configuring atomic.Bool
	reading     atomic.Int32
	// needsReconcile is set when a device change timed out; reconcileSignal
	// wakes the background loop to bring the device back in line with the store.
	needsReconcile  atomic.Bool
	reconcileSignal chan struct{}
}

type wgClient interface {
	Device(string) (*wgtypes.Device, error)
	ConfigureDevice(string, wgtypes.Config) error
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
		client:          client,
		deviceName:      cfg.WGInterface,
		subnet4:         subnet4,
		serverIP4:       serverIP4,
		subnet6:         subnet6,
		serverIP6:       serverIP6,
		store:           NewPeerStore(),
		persistPath:     cfg.PeerStoreFile,
		devCache:        newDeviceCache(deviceCacheTTL),
		reconcileSignal: make(chan struct{}, 1),
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
