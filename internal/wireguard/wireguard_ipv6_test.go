package wireguard

import (
	"errors"
	"net"
	"testing"
)

const (
	subnet6TestCIDR   = "fd00::/120"
	subnet6TestCIDR64 = "fd00::/64"
	ipv6TestAddr1     = "fd00::1"
	ipv6NextAddr      = "fd00::2"
)

func TestResolveServerIP6(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR64)
	ip, err := resolveServerIP6(subnet, ipv6TestAddr1)
	if err != nil {
		t.Fatalf("resolveServerIP6: %v", err)
	}
	if ip.String() != ipv6TestAddr1 {
		t.Errorf("got %s", ip.String())
	}

	_, err = resolveServerIP6(subnet, "not-an-ip") // invalid
	if err == nil {
		t.Error("expected error for invalid IP")
	}

	_, err = resolveServerIP6(subnet, "10.0.0.1") // IPv4
	if err == nil {
		t.Error("expected error for IPv4")
	}

	_, err = resolveServerIP6(subnet, "fd01::1") // outside subnet
	if err == nil {
		t.Error("expected error for IP outside subnet")
	}
}

func TestResolveServerIP6EmptyUsesFirst(t *testing.T) {
	_, subnet, _ := net.ParseCIDR(subnet6TestCIDR)
	ip, err := resolveServerIP6(subnet, "")
	if err != nil {
		t.Fatalf("resolveServerIP6: %v", err)
	}
	if ip == nil {
		t.Fatal("expected non-nil IP")
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

// countUsedIPv4 counts IPv4 addresses currently reserved in the pool.
func countUsedIPv4(svc *WireGuardService) int {
	if svc.pool4 == nil {
		return 0
	}
	return len(svc.pool4.used)
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
