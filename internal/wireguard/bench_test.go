package wireguard

import (
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	benchSubnet4       = "10.0.0.0/16"
	benchPeerID        = "bench-peer"
	benchPeerFmt       = "peer-%d"
	benchAllowedIP4    = "10.0.0.2/32"
	benchAllowedIP4Fmt = "10.%d.%d.2/32"
)

// newBenchService returns a WireGuardService wired to a no-op fake client,
// suitable for benchmarks that do not exercise the kernel WireGuard path.
func newBenchService(b *testing.B, cidr string) *WireGuardService {
	b.Helper()
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		b.Fatalf("parse cidr: %v", err)
	}
	server, err := resolveServerIP4(subnet, "")
	if err != nil {
		b.Fatalf("server ip: %v", err)
	}
	svc := &WireGuardService{
		client:    fakeWGClient{device: &wgtypes.Device{}},
		subnet4:   subnet,
		serverIP4: server,
		store:     NewPeerStore(),
	}
	if err := svc.initPools(); err != nil {
		b.Fatalf("initPools: %v", err)
	}
	return svc
}

// BenchmarkEnsurePeerRotate measures the rotate path: the peer already exists
// and EnsurePeer is called again to refresh its keys/expiry.
func BenchmarkEnsurePeerRotate(b *testing.B) {
	svc := newBenchService(b, benchSubnet4)
	if _, err := svc.EnsurePeer(benchPeerID, nil, []string{"IPv4"}); err != nil {
		b.Fatalf("setup: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.EnsurePeer(benchPeerID, nil, []string{"IPv4"}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEnsurePeerNew measures new peer creation. Uses a /8 subnet so that
// the IP pool is not exhausted even for large b.N values.
func BenchmarkEnsurePeerNew(b *testing.B) {
	svc := newBenchService(b, "10.0.0.0/8")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.EnsurePeer(fmt.Sprintf(benchPeerFmt, i), nil, []string{"IPv4"}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDeletePeer measures peer deletion. The peer is re-inserted outside
// the timer between iterations so that each iteration deletes a fresh record.
func BenchmarkDeletePeer(b *testing.B) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	_, ipn, _ := net.ParseCIDR(benchAllowedIP4)
	rec := PeerRecord{
		PeerID:       benchPeerID,
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   []net.IPNet{*ipn},
		CreatedAt:    time.Now().UTC(),
	}
	svc := newBenchService(b, benchSubnet4)
	svc.store.Set(rec)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.DeletePeer(benchPeerID); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		svc.store.Set(rec)
		b.StartTimer()
	}
}

// ---------- PeerStore ----------

func BenchmarkPeerStoreSet(b *testing.B) {
	store := NewPeerStore()
	key, _ := wgtypes.GenerateKey()
	_, ipn, _ := net.ParseCIDR(benchAllowedIP4)
	rec := PeerRecord{
		PeerID:     benchPeerID,
		PublicKey:  key,
		AllowedIPs: []net.IPNet{*ipn},
		CreatedAt:  time.Now().UTC(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Set(rec)
	}
}

func BenchmarkPeerStoreGet(b *testing.B) {
	store := NewPeerStore()
	key, _ := wgtypes.GenerateKey()
	_, ipn, _ := net.ParseCIDR(benchAllowedIP4)
	store.Set(PeerRecord{
		PeerID:     benchPeerID,
		PublicKey:  key,
		AllowedIPs: []net.IPNet{*ipn},
		CreatedAt:  time.Now().UTC(),
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Get(benchPeerID)
	}
}

func BenchmarkPeerStoreGetParallel(b *testing.B) {
	store := NewPeerStore()
	key, _ := wgtypes.GenerateKey()
	_, ipn, _ := net.ParseCIDR(benchAllowedIP4)
	store.Set(PeerRecord{
		PeerID:     benchPeerID,
		PublicKey:  key,
		AllowedIPs: []net.IPNet{*ipn},
		CreatedAt:  time.Now().UTC(),
	})
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			store.Get(benchPeerID)
		}
	})
}

func BenchmarkPeerStoreSetParallel(b *testing.B) {
	store := NewPeerStore()
	key, _ := wgtypes.GenerateKey()
	_, ipn, _ := net.ParseCIDR(benchAllowedIP4)
	rec := PeerRecord{
		PeerID:     benchPeerID,
		PublicKey:  key,
		AllowedIPs: []net.IPNet{*ipn},
		CreatedAt:  time.Now().UTC(),
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			store.Set(rec)
		}
	})
}

func BenchmarkPeerStoreListPaginated1000(b *testing.B) {
	store := NewPeerStore()
	for i := range 1000 {
		key, _ := wgtypes.GenerateKey()
		_, ipn, _ := net.ParseCIDR(fmt.Sprintf(benchAllowedIP4Fmt, i/256, i%256))
		store.Set(PeerRecord{
			PeerID:     fmt.Sprintf(benchPeerFmt, i),
			PublicKey:  key,
			AllowedIPs: []net.IPNet{*ipn},
			CreatedAt:  time.Now().UTC(),
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.ListPaginated(0, 50)
	}
}

func BenchmarkPeerStoreForEach1000(b *testing.B) {
	store := NewPeerStore()
	for i := range 1000 {
		key, _ := wgtypes.GenerateKey()
		_, ipn, _ := net.ParseCIDR(fmt.Sprintf(benchAllowedIP4Fmt, i/256, i%256))
		store.Set(PeerRecord{
			PeerID:     fmt.Sprintf(benchPeerFmt, i),
			PublicKey:  key,
			AllowedIPs: []net.IPNet{*ipn},
			CreatedAt:  time.Now().UTC(),
		})
	}
	n := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.ForEach(func(PeerRecord) { n++ })
	}
}

func BenchmarkPeerStorePersistPut(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "peers.db")
	store := NewPeerStore()
	if err := store.OpenFile(path); err != nil {
		b.Fatalf("OpenFile: %v", err)
	}
	defer store.Close()
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	_, ipn, _ := net.ParseCIDR(benchAllowedIP4)
	rec := PeerRecord{
		PeerID:       benchPeerID,
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   []net.IPNet{*ipn},
		CreatedAt:    time.Now().UTC(),
	}
	store.Set(rec)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := store.PersistPut(rec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPeerStoreOpenFile(b *testing.B) {
	// Prepare a DB with 200 peers to measure realistic startup load cost.
	src := NewPeerStore()
	records := make([]PeerRecord, 200)
	for i := range 200 {
		key, _ := wgtypes.GenerateKey()
		psk, _ := wgtypes.GenerateKey()
		_, ipn, _ := net.ParseCIDR(fmt.Sprintf(benchAllowedIP4Fmt, i/256, i%256))
		records[i] = PeerRecord{
			PeerID:       fmt.Sprintf(benchPeerFmt, i),
			PublicKey:    key,
			PresharedKey: psk,
			AllowedIPs:   []net.IPNet{*ipn},
			CreatedAt:    time.Now().UTC(),
		}
		src.Set(records[i])
	}
	dir := b.TempDir()
	path := filepath.Join(dir, "peers.db")
	if err := src.OpenFile(path); err != nil {
		b.Fatalf("OpenFile (prepare): %v", err)
	}
	for i := range records {
		if err := src.PersistPut(records[i]); err != nil {
			b.Fatalf("PersistPut (prepare): %v", err)
		}
	}
	src.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store := NewPeerStore()
		if err := store.OpenFile(path); err != nil {
			b.Fatal(err)
		}
		store.Close()
	}
}

// newLargeBenchService returns a service with n stored peers that are also on
// the fake device, for benchmarks at realistic node sizes.
func newLargeBenchService(b *testing.B, n int) *WireGuardService {
	b.Helper()
	_, subnet, _ := net.ParseCIDR("10.0.0.0/8")
	dev := &wgtypes.Device{Peers: make([]wgtypes.Peer, 0, n)}
	svc := &WireGuardService{subnet4: subnet, serverIP4: net.ParseIP("10.0.0.1"), store: NewPeerStore(), devCache: newDeviceCache(deviceCacheTTL)}
	base := time.Now().UTC()
	for i := range n {
		key, _ := wgtypes.GenerateKey()
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)+2).To4()
		svc.store.Set(PeerRecord{
			PeerID:     fmt.Sprintf(benchPeerFmt, i),
			PublicKey:  key,
			AllowedIPs: []net.IPNet{{IP: ip, Mask: net.CIDRMask(32, 32)}},
			CreatedAt:  base.Add(time.Duration(i)),
		})
		dev.Peers = append(dev.Peers, wgtypes.Peer{PublicKey: key})
	}
	svc.client = fakeWGClient{device: dev}
	if err := svc.initPools(); err != nil {
		b.Fatalf("initPools: %v", err)
	}
	return svc
}

// BenchmarkListPeersPage50k measures one GET /peers page at 50k peers.
func BenchmarkListPeersPage50k(b *testing.B) {
	svc := newLargeBenchService(b, 50_000)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		if _, _, err := svc.ListPeers((i*100)%50_000, 100); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCleanupExpire5kOf50k measures one expiry pass removing 5k of 50k peers.
func BenchmarkCleanupExpire5kOf50k(b *testing.B) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	b.Cleanup(func() { slog.SetDefault(prev) })
	past := time.Now().Add(-time.Hour).UTC()
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		svc := newLargeBenchService(b, 50_000)
		for i := 0; i < 50_000; i += 10 {
			rec, _ := svc.store.Get(fmt.Sprintf(benchPeerFmt, i))
			rec.ExpiresAt = &past
			svc.store.Set(rec)
		}
		b.StartTimer()
		svc.cleanupExpiredPeers()
	}
}
