package metrics

import "github.com/prometheus/client_golang/prometheus"

// WireGuardSnapshot is the aggregated kernel-level data the wgkeeper service
// can produce on demand. Mirrors wireguard.WireGuardSnapshot — kept here so
// the metrics package does not import the wireguard package.
type WireGuardSnapshot struct {
	ReceiveBytesTotal  int64
	TransmitBytesTotal int64
	StalePeers         int
}

// WireGuardProvider returns aggregated WireGuard kernel state. The wireguard
// service satisfies this via a thin adapter.
type WireGuardProvider interface {
	WireGuardSnapshot() (WireGuardSnapshot, error)
}

// BindWireGuardProvider registers a Collector that emits aggregated kernel
// metrics — total rx/tx bytes and the count of peers with stale handshakes —
// lazily on every scrape. The provider is expected to read from a short-TTL
// cache so the scrape does not flood netlink under tight intervals.
//
// On provider error all three metrics are omitted from the response. Absence
// is a cleaner signal than zero values that would otherwise look like a flat
// line on the dashboard.
func (m *Metrics) BindWireGuardProvider(p WireGuardProvider) {
	rx := prometheus.NewDesc(
		"wgkeeper_wireguard_rx_bytes_total",
		"Total bytes received across all WireGuard peers since interface bring-up.",
		nil, nil,
	)
	tx := prometheus.NewDesc(
		"wgkeeper_wireguard_tx_bytes_total",
		"Total bytes transmitted across all WireGuard peers since interface bring-up.",
		nil, nil,
	)
	stale := prometheus.NewDesc(
		"wgkeeper_wireguard_stale_peers",
		"Peers with no handshake within the last 5 minutes (or that have never handshaken).",
		nil, nil,
	)
	m.registry.MustRegister(&wgCollector{
		provider:  p,
		rxDesc:    rx,
		txDesc:    tx,
		staleDesc: stale,
	})
}

type wgCollector struct {
	provider  WireGuardProvider
	rxDesc    *prometheus.Desc
	txDesc    *prometheus.Desc
	staleDesc *prometheus.Desc
}

func (c *wgCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.rxDesc
	ch <- c.txDesc
	ch <- c.staleDesc
}

func (c *wgCollector) Collect(ch chan<- prometheus.Metric) {
	snap, err := c.provider.WireGuardSnapshot()
	if err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.rxDesc, prometheus.CounterValue, float64(snap.ReceiveBytesTotal))
	ch <- prometheus.MustNewConstMetric(c.txDesc, prometheus.CounterValue, float64(snap.TransmitBytesTotal))
	ch <- prometheus.MustNewConstMetric(c.staleDesc, prometheus.GaugeValue, float64(snap.StalePeers))
}
