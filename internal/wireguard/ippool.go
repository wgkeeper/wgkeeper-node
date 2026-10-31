package wireguard

import (
	"container/heap"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// maxReportedCapacity caps the peer capacity reported for huge subnets (an
// IPv6 /64 holds 2^64 addresses) at a value that still fits a float64
// exactly, so /stats and the wgkeeper_peers gauge stay precise.
const maxReportedCapacity = 1 << 53

// ipPool hands out the host addresses of one subnet. Allocation takes the
// lowest released address first, then advances a cursor through addresses
// never handed out. The cursor visits each address at most once per process,
// so allocation is O(log n) amortized whatever the subnet size, and every
// free address is eventually found: there is no scan limit. Not safe for
// concurrent use; the service guards it with s.mu.
type ipPool struct {
	prefix   netip.Prefix
	first    netip.Addr // first usable host (network + 1)
	last     netip.Addr // last usable host (broadcast - 1)
	used     map[netip.Addr]struct{}
	released addrHeap   // freed addresses below cursor, lowest first
	cursor   netip.Addr // next address the cursor will try; invalid once past last
	capacity int        // usable host addresses minus the server address, capped
}

func newIPPool(prefix netip.Prefix, server netip.Addr) (*ipPool, error) {
	prefix = prefix.Masked()
	first, last, err := hostRange(prefix)
	if err != nil {
		return nil, err
	}
	p := &ipPool{
		prefix: prefix,
		first:  first,
		last:   last,
		used:   make(map[netip.Addr]struct{}),
		cursor: first,
	}
	p.capacity = hostCount(prefix)
	if server.IsValid() && p.inRange(server) {
		p.used[server] = struct{}{}
		p.capacity--
	}
	return p, nil
}

// hostRange returns the first and last usable host of prefix, excluding the
// network and broadcast addresses.
func hostRange(prefix netip.Prefix) (first, last netip.Addr, err error) {
	bits := prefix.Addr().BitLen()
	if bits-prefix.Bits() < 2 {
		return netip.Addr{}, netip.Addr{}, errors.New("subnet is too small: it needs room for the server and at least one peer")
	}
	network := prefix.Addr()
	broadcast := lastAddr(prefix)
	return network.Next(), broadcast.Prev(), nil
}

// lastAddr returns the highest address in prefix.
func lastAddr(prefix netip.Prefix) netip.Addr {
	b := prefix.Addr().AsSlice()
	for i := prefix.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// hostCount is the number of usable hosts in prefix, capped at maxReportedCapacity.
func hostCount(prefix netip.Prefix) int {
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits >= 53 {
		return maxReportedCapacity
	}
	return 1<<hostBits - 2
}

func (p *ipPool) inRange(a netip.Addr) bool {
	return a.Compare(p.first) >= 0 && a.Compare(p.last) <= 0
}

// markUsed records an address already held by a stored peer.
func (p *ipPool) markUsed(a netip.Addr) {
	p.used[a] = struct{}{}
}

func (p *ipPool) isUsed(a netip.Addr) bool {
	_, ok := p.used[a]
	return ok
}

// allocate reserves and returns a free address, or ErrNoAvailableIP.
func (p *ipPool) allocate() (netip.Addr, error) {
	for p.released.Len() > 0 {
		a, ok := heap.Pop(&p.released).(netip.Addr)
		if ok && !p.isUsed(a) {
			p.used[a] = struct{}{}
			return a, nil
		}
	}
	for p.cursor.IsValid() && p.cursor.Compare(p.last) <= 0 {
		a := p.cursor
		p.cursor = a.Next()
		if !p.isUsed(a) {
			p.used[a] = struct{}{}
			return a, nil
		}
	}
	p.cursor = netip.Addr{}
	return netip.Addr{}, ErrNoAvailableIP
}

// release frees an address so a later allocate can hand it out again.
func (p *ipPool) release(a netip.Addr) {
	if !p.isUsed(a) || !p.inRange(a) {
		return
	}
	delete(p.used, a)
	if !p.cursor.IsValid() || a.Compare(p.cursor) < 0 {
		heap.Push(&p.released, a)
	}
}

// addrHeap is a min-heap of addresses for container/heap.
type addrHeap []netip.Addr

func (h addrHeap) Len() int           { return len(h) }
func (h addrHeap) Less(i, j int) bool { return h[i].Less(h[j]) }
func (h addrHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *addrHeap) Push(x any) {
	if a, ok := x.(netip.Addr); ok {
		*h = append(*h, a)
	}
}
func (h *addrHeap) Pop() any {
	old := *h
	a := old[len(old)-1]
	*h = old[:len(old)-1]
	return a
}

// addrFromIP converts a net.IP to netip.Addr, unmapping IPv4-in-IPv6.
func addrFromIP(ip net.IP) netip.Addr {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return a.Unmap()
}

// prefixFromIPNet converts a net.IPNet to netip.Prefix.
func prefixFromIPNet(n *net.IPNet) (netip.Prefix, error) {
	a := addrFromIP(n.IP)
	if !a.IsValid() {
		return netip.Prefix{}, errors.New("invalid subnet address")
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(a, ones).Masked(), nil
}

// hostIPNet returns a as a single-host net.IPNet (/32 or /128).
func hostIPNet(a netip.Addr) net.IPNet {
	bits := a.BitLen()
	return net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(bits, bits)}
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
