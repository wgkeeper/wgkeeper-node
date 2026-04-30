package metrics

import (
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// PeerSnapshot is the per-peer view that the wireguard service produces. The
// metrics package mirrors the type so the wireguard package keeps no
// prometheus dependency.
type PeerSnapshot struct {
	PeerID                  string
	AllowedIP               string
	ReceiveBytes            int64
	TransmitBytes           int64
	LastHandshakeAgeSeconds float64
}

// PerPeerProvider returns the full per-peer snapshot. The collector applies
// the cardinality cap; the provider always returns every peer it knows about.
type PerPeerProvider interface {
	PeersSnapshot() ([]PeerSnapshot, error)
}

// BindPerPeerProvider registers a Collector that emits per-peer Prometheus
// metrics with a hard cardinality cap. The collector keeps top-N peers by
// the delta of (rx + tx) since the previous scrape — i.e. who is busy *now*,
// not who has accumulated the most traffic since interface bring-up.
//
// Metrics emitted (only the top-N at scrape time):
//
//	wgkeeper_peer_rx_bytes_total{peer_id, allowed_ip}        counter
//	wgkeeper_peer_tx_bytes_total{peer_id, allowed_ip}        counter
//	wgkeeper_peer_last_handshake_seconds{peer_id, allowed_ip} gauge (age)
//
// And one always-emitted summary metric (no labels):
//
//	wgkeeper_peers_capped                                     gauge — peers
//	    that were excluded from per-peer metrics by the cap. 0 when N <= max.
//
// max <= 0 means "do not register" — caller should not call BindPerPeerProvider
// in that case.
func (m *Metrics) BindPerPeerProvider(p PerPeerProvider, max int) {
	if max <= 0 {
		return
	}
	c := &peerCollector{
		provider: p,
		max:      max,
		prevSum:  make(map[string]int64),
		rxDesc: prometheus.NewDesc(
			"wgkeeper_peer_rx_bytes_total",
			"Per-peer received bytes (kernel counter). Cardinality bounded by metrics.per_peer_max — top-N by recent traffic.",
			[]string{"peer_id", "allowed_ip"}, nil,
		),
		txDesc: prometheus.NewDesc(
			"wgkeeper_peer_tx_bytes_total",
			"Per-peer transmitted bytes (kernel counter). Cardinality bounded by metrics.per_peer_max — top-N by recent traffic.",
			[]string{"peer_id", "allowed_ip"}, nil,
		),
		hsDesc: prometheus.NewDesc(
			"wgkeeper_peer_last_handshake_seconds",
			"Seconds since last WireGuard handshake. +Inf when the peer has never handshaken. Cardinality bounded by metrics.per_peer_max.",
			[]string{"peer_id", "allowed_ip"}, nil,
		),
		cappedDesc: prometheus.NewDesc(
			"wgkeeper_peers_capped",
			"Number of peers excluded from per-peer metrics by the metrics.per_peer_max cap. Stays 0 unless the cap is hit.",
			nil, nil,
		),
	}
	m.registry.MustRegister(c)
}

// peerCollector emits per-peer metrics with a top-N cap and a "capped" summary.
//
// The collector tracks the previous (rx + tx) sum per peer_id between scrapes,
// so it can rank peers by *recent* delta rather than lifetime totals. Newly
// busy peers surface immediately; long-quiet peers fall out of the top-N.
type peerCollector struct {
	provider PerPeerProvider
	max      int

	mu      sync.Mutex
	prevSum map[string]int64

	rxDesc, txDesc, hsDesc, cappedDesc *prometheus.Desc
}

func (c *peerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.rxDesc
	ch <- c.txDesc
	ch <- c.hsDesc
	ch <- c.cappedDesc
}

func (c *peerCollector) Collect(ch chan<- prometheus.Metric) {
	peers, err := c.provider.PeersSnapshot()
	if err != nil {
		// Match the rest of the package: on provider error, emit nothing.
		// Prometheus will report stale but not zero — operator sees the gap.
		return
	}

	total := len(peers)
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update prevSum for every peer (even those we won't emit) so a peer that
	// drops out of the top-N this scrape and rejoins next has a correct delta.
	type ranked struct {
		idx   int
		delta int64
	}
	ranks := make([]ranked, 0, total)
	currSum := make(map[string]int64, total)
	for i, p := range peers {
		sum := p.ReceiveBytes + p.TransmitBytes
		prev := c.prevSum[p.PeerID]
		delta := sum - prev
		if delta < 0 {
			// Counter reset (interface recreated). Treat as full current
			// value — the peer is "newly busy" from the dashboard's view.
			delta = sum
		}
		currSum[p.PeerID] = sum
		ranks = append(ranks, ranked{idx: i, delta: delta})
	}
	c.prevSum = currSum

	// Sort by delta desc; tiebreak by peer_id for determinism.
	sort.Slice(ranks, func(i, j int) bool {
		if ranks[i].delta != ranks[j].delta {
			return ranks[i].delta > ranks[j].delta
		}
		return peers[ranks[i].idx].PeerID < peers[ranks[j].idx].PeerID
	})

	emit := total
	capped := 0
	if total > c.max {
		emit = c.max
		capped = total - c.max
	}

	for i := 0; i < emit; i++ {
		p := peers[ranks[i].idx]
		ch <- prometheus.MustNewConstMetric(c.rxDesc, prometheus.CounterValue, float64(p.ReceiveBytes), p.PeerID, p.AllowedIP)
		ch <- prometheus.MustNewConstMetric(c.txDesc, prometheus.CounterValue, float64(p.TransmitBytes), p.PeerID, p.AllowedIP)
		ch <- prometheus.MustNewConstMetric(c.hsDesc, prometheus.GaugeValue, p.LastHandshakeAgeSeconds, p.PeerID, p.AllowedIP)
	}
	ch <- prometheus.MustNewConstMetric(c.cappedDesc, prometheus.GaugeValue, float64(capped))
}
