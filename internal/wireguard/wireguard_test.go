package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	msgUnexpectedError     = "unexpected error: %v"
	msgListPeersFmt        = "ListPeers: %v"
	msgSavePeerStoreErr    = "expected 'save peer store' in error, got %v"
	peersDBFile            = "/peers.db"
	persistPathNonexistent = "/nonexistent-dir-xyz/peers.db"
	savePeerStoreSubstr    = "save peer store"
	ipServerTest           = "10.0.0.1"
	ipPeerTest             = "10.0.0.2"
	peerIDTest             = "peer-1"
	peerIDNewPeer          = "new-peer"
	subnetTestCIDR         = "10.0.0.0/24"
	subnetSmallTestCIDR    = "10.0.0.0/29"
)

type fakeWGClient struct {
	device       *wgtypes.Device
	err          error
	configureErr error
}

func (f fakeWGClient) Device(_ string) (*wgtypes.Device, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.device, nil
}

func (f fakeWGClient) ConfigureDevice(_ string, _ wgtypes.Config) error {
	return f.configureErr
}

func ipNet(t *testing.T, ip string) net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(fmt.Sprintf("%s/32", ip))
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	return *n
}

func TestValidateAddressFamiliesEmptyReturnsNodeFamilies(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{subnet4: subnet4, serverIP4: net.ParseIP(ipServerTest), store: NewPeerStore()}
	families, err := svc.ValidateAddressFamilies(nil)
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(families) != 1 || families[0] != FamilyIPv4 {
		t.Fatalf("expected [IPv4], got %v", families)
	}
}

func TestValidateAddressFamiliesUnsupported(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{subnet4: subnet4, serverIP4: net.ParseIP(ipServerTest), store: NewPeerStore()}
	_, err := svc.ValidateAddressFamilies([]string{FamilyIPv6})
	if !errors.Is(err, ErrUnsupportedAddressFamily) {
		t.Fatalf("expected ErrUnsupportedAddressFamily, got %v", err)
	}
}

func newTestServiceWithSubnet29(t *testing.T, device *wgtypes.Device) *WireGuardService {
	t.Helper()
	_, subnet, _ := net.ParseCIDR(subnetSmallTestCIDR)
	return &WireGuardService{
		client:     fakeWGClient{device: device},
		deviceName: "wg0",
		subnet4:    subnet,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
}

func newTestServiceWithSubnet(t *testing.T, configureErr error) *WireGuardService {
	t.Helper()
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	return &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}, configureErr: configureErr},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
}

func ipNet6(t *testing.T, ip string) net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(ip + "/128")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	return *n
}

// openAndBreakDB opens the store DB at path, then closes the underlying bolt.DB
// directly (without calling store.Close) so that store.db is non-nil but closed.
// Subsequent PersistPut/PersistDeleteBatch calls will return an error.
func openAndBreakDB(t *testing.T, store *PeerStore, path string) {
	t.Helper()
	if err := store.OpenFile(path); err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	// Close the bbolt DB directly, leaving store.db non-nil so persist methods
	// attempt the write and return the "database not open" error.
	_ = store.db.Close()
}

func TestNodeAddressFamiliesNone(t *testing.T) {
	svc := &WireGuardService{}
	fams := svc.NodeAddressFamilies()
	if len(fams) != 0 {
		t.Fatalf("expected 0 families, got %v", fams)
	}
}

// persistedRecord reopens the bbolt file behind svc after closing it and
// reports whether peerID is stored there.
func persistedRecord(t *testing.T, svc *WireGuardService, path, peerID string) bool {
	t.Helper()
	if err := svc.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	reopened := NewPeerStore()
	if err := reopened.OpenFile(path); err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	_, ok := reopened.Get(peerID)
	return ok
}

func newPersistedTestService(t *testing.T, configureErr error) (*WireGuardService, PeerRecord, string) {
	t.Helper()
	svc := newTestServiceWithSubnet(t, configureErr)
	path := t.TempDir() + peersDBFile
	if err := svc.store.OpenFile(path); err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	key, _ := wgtypes.GenerateKey()
	record := PeerRecord{
		PeerID:       peerIDTest,
		PublicKey:    key,
		PresharedKey: wgtypes.Key{},
		AllowedIPs:   []net.IPNet{ipNet(t, ipPeerTest)},
		CreatedAt:    time.Now().UTC(),
	}
	if err := svc.store.PersistPut(record); err != nil {
		t.Fatalf("PersistPut: %v", err)
	}
	svc.store.Set(record)
	markIPUsed(t, svc, ipPeerTest)
	return svc, record, path
}

// recordingWGClient captures every ConfigureDevice call for assertions.
type recordingWGClient struct {
	device         *wgtypes.Device
	err            error
	configureErr   error
	configureCalls []wgtypes.Config
}

func (c *recordingWGClient) Device(_ string) (*wgtypes.Device, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.device, nil
}

func (c *recordingWGClient) ConfigureDevice(_ string, cfg wgtypes.Config) error {
	c.configureCalls = append(c.configureCalls, cfg)
	return c.configureErr
}

// ipInUse reports whether the service's pools consider ip taken.
func ipInUse(t *testing.T, svc *WireGuardService, ip string) bool {
	t.Helper()
	if svc.pool4 == nil && svc.pool6 == nil {
		if err := svc.initPools(); err != nil {
			t.Fatalf("initPools: %v", err)
		}
	}
	a := netip.MustParseAddr(ip)
	if a.Is4() {
		return svc.pool4 != nil && svc.pool4.isUsed(a)
	}
	return svc.pool6 != nil && svc.pool6.isUsed(a)
}

// markIPUsed records ip as taken, as if a stored peer held it.
func markIPUsed(t *testing.T, svc *WireGuardService, ip string) {
	t.Helper()
	ipInUse(t, svc, ip) // initialises the pools
	a := netip.MustParseAddr(ip)
	if a.Is4() {
		svc.pool4.markUsed(a)
		return
	}
	svc.pool6.markUsed(a)
}

func TestNodeAddressFamiliesDualStack(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{subnet4: subnet4, subnet6: subnet6}
	if families := svc.NodeAddressFamilies(); len(families) != 2 {
		t.Errorf("expected two families, got %v", families)
	}
}

// subnetTestCIDR, ipServerTest, msgUnexpectedError — from wireguard_test.go (same package)
// subnet6TestCIDR, subnet6TestCIDR64, ipv6TestAddr1  — from wireguard_ipv6_test.go (same package)
const (
	testSubnet31       = "10.0.0.0/31"
	testSubnet6        = "fd00::/112"
	testServerIP6InBig = "fd00::5"
	testServerIP6Out   = "fd01::1"

	testPeerIP4                  = "10.0.0.2/32"
	testOutsidePeerID            = "outside-peer"
	testErrDeviceBusyMessage     = "device busy"
	testErrDeviceError           = "device error"
	testErrDeviceOffline         = "device offline"
	testExpiryPeerID             = "expiry-peer"
	testDelFailPeerID            = "del-fail"
	msgExpectedTwoFamilies       = "expected 2 families, got %v"
	msgExpectedDeviceUnavailable = "expected error when device is unavailable"
)

func newValidateTestService(t *testing.T) *WireGuardService {
	t.Helper()
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	return &WireGuardService{
		client:     fakeWGClient{device: &wgtypes.Device{}},
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
	}
}

func setTestPeer(t *testing.T, svc *WireGuardService, peerID, cidr string) {
	t.Helper()
	key, _ := wgtypes.GenerateKey()
	svc.store.Set(PeerRecord{PeerID: peerID, PublicKey: key, AllowedIPs: mustParseCIDRs(t, cidr)})
}

func TestValidateAddressFamiliesBothFamilies(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{
		subnet4:   subnet4,
		serverIP4: net.ParseIP(ipServerTest),
		subnet6:   subnet6,
		serverIP6: net.ParseIP(ipv6TestAddr1),
		store:     NewPeerStore(),
	}
	families, err := svc.ValidateAddressFamilies([]string{FamilyIPv4, FamilyIPv6})
	if err != nil {
		t.Fatalf(msgUnexpectedError, err)
	}
	if len(families) != 2 {
		t.Errorf(msgExpectedTwoFamilies, families)
	}
}

func TestValidateAddressFamiliesIPv4OnlyNode(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{
		subnet4:   subnet4,
		serverIP4: net.ParseIP(ipServerTest),
		store:     NewPeerStore(),
	}
	// Requesting IPv6 from IPv4-only node
	_, err := svc.ValidateAddressFamilies([]string{FamilyIPv6})
	if !errors.Is(err, ErrUnsupportedAddressFamily) {
		t.Fatalf("expected ErrUnsupportedAddressFamily, got %v", err)
	}
}

func TestValidateAddressFamiliesInvalidFamilyName(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	svc := &WireGuardService{subnet4: subnet4, store: NewPeerStore()}
	_, err := svc.ValidateAddressFamilies([]string{"InvalidFamily"})
	if err == nil {
		t.Fatal("expected error for unknown address family")
	}
}

func TestValidateAddressFamiliesDuplicateFamily(t *testing.T) {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	_, subnet6, _ := net.ParseCIDR(testSubnet6)
	svc := &WireGuardService{subnet4: subnet4, subnet6: subnet6, store: NewPeerStore()}
	_, err := svc.ValidateAddressFamilies([]string{FamilyIPv4, FamilyIPv4})
	if err == nil {
		t.Fatal("expected error for duplicate address family")
	}
}

// fakeWGClientFunc adapts a function to the wgClient interface (Device only).
type fakeWGClientFunc func() (*wgtypes.Device, error)

func (f fakeWGClientFunc) Device(_ string) (*wgtypes.Device, error) { return f() }

func (f fakeWGClientFunc) ConfigureDevice(_ string, _ wgtypes.Config) error { return nil }

func newSvcWithCache(client wgClient, cacheTTL time.Duration) *WireGuardService {
	_, subnet4, _ := net.ParseCIDR(subnetTestCIDR)
	return &WireGuardService{
		client:     client,
		deviceName: "wg0",
		subnet4:    subnet4,
		serverIP4:  net.ParseIP(ipServerTest),
		store:      NewPeerStore(),
		devCache:   newDeviceCache(cacheTTL),
	}
}

// countingClient counts how many times Device() is called.
type countingClient struct {
	calls int
	dev   *wgtypes.Device
}

func (c *countingClient) Device(_ string) (*wgtypes.Device, error) {
	c.calls++
	return c.dev, nil
}

func (c *countingClient) ConfigureDevice(_ string, _ wgtypes.Config) error {
	return nil
}

// blockingClient blocks forever on Device, simulating a hung kernel module.
type blockingClient struct{ done chan struct{} }

func newBlockingClient() blockingClient { return blockingClient{done: make(chan struct{})} }

func (b blockingClient) Device(_ string) (*wgtypes.Device, error) {
	<-b.done
	return nil, errors.New("unblocked")
}

func (b blockingClient) ConfigureDevice(_ string, _ wgtypes.Config) error { return nil }

// blockingConfigureClient blocks ConfigureDevice until released.
type blockingConfigureClient struct {
	done   chan struct{}
	device *wgtypes.Device
}

func (b blockingConfigureClient) Device(_ string) (*wgtypes.Device, error) { return b.device, nil }

func (b blockingConfigureClient) ConfigureDevice(_ string, _ wgtypes.Config) error {
	<-b.done
	return nil
}

const (
	subnet6TestCIDR   = "fd00::/120"
	subnet6TestCIDR64 = "fd00::/64"
	ipv6TestAddr1     = "fd00::1"
	ipv6NextAddr      = "fd00::2"
)

// countUsedIPv4 counts IPv4 addresses currently reserved in the pool.
func countUsedIPv4(svc *WireGuardService) int {
	if svc.pool4 == nil {
		return 0
	}
	return len(svc.pool4.used)
}
