package metrics

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakePerPeerProvider returns a configurable peer list and optional error.
type fakePerPeerProvider struct {
	peers []PeerSnapshot
	err   error
}

func (f *fakePerPeerProvider) PeersSnapshot() ([]PeerSnapshot, error) {
	return f.peers, f.err
}

// gatherCount returns how many series the metrics package emits across all
// per-peer metric names — useful for asserting cap behaviour without parsing
// individual values.
func gatherPerPeerCount(t *testing.T, m *Metrics) (peerSeries int, capped float64) {
	t.Helper()
	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		switch mf.GetName() {
		case "wgkeeper_peer_rx_bytes_total",
			"wgkeeper_peer_tx_bytes_total",
			"wgkeeper_peer_last_handshake_seconds":
			peerSeries += len(mf.Metric)
		case "wgkeeper_peers_capped":
			if len(mf.Metric) == 1 && mf.Metric[0].Gauge != nil {
				capped = mf.Metric[0].Gauge.GetValue()
			}
		}
	}
	return peerSeries, capped
}

func TestPerPeerCollectorEmitsAllMetricsBelowCap(t *testing.T) {
	m := New()
	provider := &fakePerPeerProvider{
		peers: []PeerSnapshot{
			{PeerID: "a", AllowedIP: "10.0.0.2/32", ReceiveBytes: 100, TransmitBytes: 200, LastHandshakeAgeSeconds: 30},
			{PeerID: "b", AllowedIP: "10.0.0.3/32", ReceiveBytes: 50, TransmitBytes: 60, LastHandshakeAgeSeconds: 90},
		},
	}
	m.BindPerPeerProvider(provider, 100)

	peerSeries, capped := gatherPerPeerCount(t, m)
	// 2 peers × 3 metrics each = 6 series. Plus capped gauge = 0.
	if peerSeries != 6 {
		t.Errorf("expected 6 per-peer series (2 peers × 3 metrics), got %d", peerSeries)
	}
	if capped != 0 {
		t.Errorf("expected capped=0 below cap, got %v", capped)
	}
}

func TestPerPeerCollectorAppliesCap(t *testing.T) {
	m := New()
	// 10 peers, cap 3 → emit 3, capped = 7
	peers := make([]PeerSnapshot, 10)
	for i := range peers {
		peers[i] = PeerSnapshot{
			PeerID:        fmt.Sprintf("peer-%d", i),
			AllowedIP:     fmt.Sprintf("10.0.0.%d/32", i+2),
			ReceiveBytes:  int64(i * 1000),
			TransmitBytes: int64(i * 500),
		}
	}
	m.BindPerPeerProvider(&fakePerPeerProvider{peers: peers}, 3)

	peerSeries, capped := gatherPerPeerCount(t, m)
	if peerSeries != 9 { // 3 peers × 3 metrics
		t.Errorf("expected 9 series (3 peers × 3 metrics), got %d", peerSeries)
	}
	if capped != 7 {
		t.Errorf("expected capped=7, got %v", capped)
	}
}

func TestPerPeerCollectorRanksByDelta(t *testing.T) {
	// "delta-based top-N" means a peer that just started transferring
	// outranks a peer with a large historical total but no recent activity.
	m := New()
	provider := &fakePerPeerProvider{
		peers: []PeerSnapshot{
			{PeerID: "old-heavy", ReceiveBytes: 1_000_000, TransmitBytes: 1_000_000},
			{PeerID: "newcomer", ReceiveBytes: 100, TransmitBytes: 100},
		},
	}
	m.BindPerPeerProvider(provider, 1)

	// Scrape 1: trigger a collection to populate prevSum (we don't assert on
	// the result — we only care that the second scrape sees a baseline).
	_, _ = gatherPerPeerCount(t, m)

	// Scrape 2: newcomer adds traffic, old-heavy unchanged.
	provider.peers[0].ReceiveBytes = 1_000_000 // unchanged
	provider.peers[0].TransmitBytes = 1_000_000
	provider.peers[1].ReceiveBytes = 50_000 // delta = 49_900
	provider.peers[1].TransmitBytes = 50_000

	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	// Find the rx metric and check which peer_id was emitted (only 1 due to cap).
	var emittedPeerID string
	for _, mf := range mfs {
		if mf.GetName() != "wgkeeper_peer_rx_bytes_total" {
			continue
		}
		for _, mm := range mf.Metric {
			for _, l := range mm.Label {
				if l.GetName() == "peer_id" {
					emittedPeerID = l.GetValue()
				}
			}
		}
	}
	if emittedPeerID != "newcomer" {
		t.Errorf("expected delta-ranking to surface 'newcomer', got %q", emittedPeerID)
	}
}

func TestPerPeerCollectorOmitsOnError(t *testing.T) {
	m := New()
	m.BindPerPeerProvider(&fakePerPeerProvider{err: errors.New("device unavailable")}, 100)

	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		switch mf.GetName() {
		case "wgkeeper_peer_rx_bytes_total",
			"wgkeeper_peer_tx_bytes_total",
			"wgkeeper_peer_last_handshake_seconds",
			"wgkeeper_peers_capped":
			t.Errorf("metric %q should be absent when provider errors", mf.GetName())
		}
	}
}

func TestPerPeerCollectorCounterResetHandled(t *testing.T) {
	// Interface restart resets kernel counters to zero. The collector must
	// not crash on negative delta — it treats the new value as the delta.
	m := New()
	provider := &fakePerPeerProvider{
		peers: []PeerSnapshot{
			{PeerID: "a", ReceiveBytes: 1_000_000, TransmitBytes: 0},
		},
	}
	m.BindPerPeerProvider(provider, 10)

	// Scrape 1: populate prevSum.
	_, _ = gatherPerPeerCount(t, m)

	// Scrape 2: counters reset.
	provider.peers[0].ReceiveBytes = 100
	_, _ = gatherPerPeerCount(t, m)

	// Should not panic — and the peer should still be emitted.
	out := gatherAsText(t, m)
	if !strings.Contains(out, `wgkeeper_peer_rx_bytes_total{`) {
		t.Error("peer should remain in metrics after counter reset")
	}
}

func TestBindPerPeerProviderZeroMaxIsNoop(t *testing.T) {
	m := New()
	m.BindPerPeerProvider(&fakePerPeerProvider{
		peers: []PeerSnapshot{{PeerID: "a", ReceiveBytes: 1}},
	}, 0)

	out := gatherAsText(t, m)
	if strings.Contains(out, "wgkeeper_peer_") {
		t.Error("max=0 must not register the collector")
	}
}
