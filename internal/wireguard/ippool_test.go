package wireguard

import (
	"errors"
	"net/netip"
	"testing"
)

func mustPool(t *testing.T, prefix, server string) *ipPool {
	t.Helper()
	var srv netip.Addr
	if server != "" {
		srv = netip.MustParseAddr(server)
	}
	p, err := newIPPool(netip.MustParsePrefix(prefix), srv)
	if err != nil {
		t.Fatalf("newIPPool(%s): %v", prefix, err)
	}
	return p
}

func mustAllocate(t *testing.T, p *ipPool) netip.Addr {
	t.Helper()
	a, err := p.allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	return a
}

func TestIPPoolAllocatesInOrderAndSkipsServer(t *testing.T) {
	p := mustPool(t, "10.0.0.0/29", "10.0.0.1")
	var got []string
	for range 5 {
		got = append(got, mustAllocate(t, p).String())
	}
	want := []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("allocation %d: got %s, want %s (all: %v)", i, got[i], want[i], got)
		}
	}
	if _, err := p.allocate(); !errors.Is(err, ErrNoAvailableIP) {
		t.Fatalf("full /29: got %v, want ErrNoAvailableIP", err)
	}
}

func TestIPPoolReusesLowestReleased(t *testing.T) {
	p := mustPool(t, "10.0.0.0/24", "10.0.0.1")
	for range 10 {
		mustAllocate(t, p)
	}
	p.release(netip.MustParseAddr("10.0.0.7"))
	p.release(netip.MustParseAddr("10.0.0.4"))
	if a := mustAllocate(t, p); a.String() != "10.0.0.4" {
		t.Fatalf("got %s, want lowest released 10.0.0.4", a)
	}
	if a := mustAllocate(t, p); a.String() != "10.0.0.7" {
		t.Fatalf("got %s, want 10.0.0.7", a)
	}
	if a := mustAllocate(t, p); a.String() != "10.0.0.12" {
		t.Fatalf("got %s, want the next fresh address 10.0.0.12", a)
	}
}

func TestIPPoolSkipsAddressesMarkedUsed(t *testing.T) {
	p := mustPool(t, "10.0.0.0/24", "10.0.0.1")
	p.markUsed(netip.MustParseAddr("10.0.0.2"))
	p.markUsed(netip.MustParseAddr("10.0.0.3"))
	if a := mustAllocate(t, p); a.String() != "10.0.0.4" {
		t.Fatalf("got %s, want 10.0.0.4", a)
	}
}

// TestIPPoolLargeSubnetHasNoScanLimit guards against the old allocator's
// 65,536-step cap, which reported "no available IP" on big subnets with free
// space left.
func TestIPPoolLargeSubnetHasNoScanLimit(t *testing.T) {
	p := mustPool(t, "fd00::/64", "fd00::1")
	for range 70_000 {
		mustAllocate(t, p)
	}
	p.release(netip.MustParseAddr("fd00::a"))
	if a := mustAllocate(t, p); a.String() != "fd00::a" {
		t.Fatalf("got %s, want released fd00::a", a)
	}
	mustAllocate(t, p)
}

func TestIPPoolReleaseIgnoresUnknownAddresses(t *testing.T) {
	p := mustPool(t, "10.0.0.0/30", "10.0.0.1")
	p.release(netip.MustParseAddr("192.168.0.5"))
	p.release(netip.MustParseAddr("10.0.0.2")) // never allocated
	if a := mustAllocate(t, p); a.String() != "10.0.0.2" {
		t.Fatalf("got %s, want 10.0.0.2", a)
	}
	if _, err := p.allocate(); !errors.Is(err, ErrNoAvailableIP) {
		t.Fatalf("got %v, want ErrNoAvailableIP", err)
	}
}

func TestIPPoolCapacity(t *testing.T) {
	cases := []struct {
		prefix, server string
		want           int
	}{
		{"10.0.0.0/30", "10.0.0.1", 1},
		{"10.0.0.0/24", "10.0.0.1", 253},
		{"10.0.0.0/24", "", 254},
		{"10.0.0.0/16", "10.0.0.1", 65533},
		{"fd00::/112", "fd00::1", 65533},
		{"fd00::/64", "fd00::1", maxReportedCapacity - 1},
	}
	for _, tc := range cases {
		if got := mustPool(t, tc.prefix, tc.server).capacity; got != tc.want {
			t.Errorf("%s server=%q: capacity %d, want %d", tc.prefix, tc.server, got, tc.want)
		}
	}
}

func TestNewIPPoolRejectsTinySubnets(t *testing.T) {
	for _, prefix := range []string{"10.0.0.0/31", "10.0.0.0/32", "fd00::/127"} {
		if _, err := newIPPool(netip.MustParsePrefix(prefix), netip.Addr{}); err == nil {
			t.Errorf("%s: expected an error", prefix)
		}
	}
}

func BenchmarkIPPoolAllocateAfterDelete(b *testing.B) {
	p, _ := newIPPool(netip.MustParsePrefix("10.0.0.0/16"), netip.MustParseAddr("10.0.0.1"))
	addrs := make([]netip.Addr, 50_000)
	for i := range addrs {
		addrs[i], _ = p.allocate()
	}
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		a := addrs[i%len(addrs)]
		p.release(a)
		got, err := p.allocate()
		if err != nil || got != a {
			b.Fatalf("got %v, %v; want %v", got, err, a)
		}
	}
}
