// Package metrics exposes runtime metrics in Prometheus exposition format.
//
// The endpoint is opt-in (config.metrics.port = 0 disables it). When enabled
// it runs on a separate HTTP listener with a mandatory bearer token — distinct
// from auth.api_key — so that compromise of the scrape secret does not grant
// peer-management access.
//
// Cardinality discipline: every label is from a fixed enum (op, result,
// state). Per-peer or request-id labels are intentionally absent — they would
// blow series count on any non-trivial deployment.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Operation enumerates peer-lifecycle operations exposed via metrics.
const (
	OpCreate = "create"
	OpRotate = "rotate"
	OpDelete = "delete"
	OpExpire = "expire"
)

// Result enumerates the coarse-grained outcomes of a peer operation. Labels
// are intentionally a small fixed set; do not extend without thinking through
// cardinality.
const (
	ResultSuccess             = "success"
	ResultErrorNoIP           = "error_no_ip"
	ResultErrorPersist        = "error_persist"
	ResultErrorDevice         = "error_device"
	ResultErrorUnsupportedFam = "error_unsupported_family"
	ResultErrorNotFound       = "error_not_found"
	ResultErrorInternal       = "error_internal"
)

// PeerState enumerates the bucket reported by the peers gauge.
const (
	StatePossible = "possible"
	StateIssued   = "issued"
	StateActive   = "active"
)

// Metrics is the registry-bound bundle of wgkeeper metrics. It is constructed
// once at startup and threaded into the WireGuardService and HTTP handlers.
type Metrics struct {
	registry *prometheus.Registry

	// PeerOps counts every peer-lifecycle attempt, labelled by op and result.
	// Used to derive error rates: rate(... result!="success") / rate(...).
	PeerOps *prometheus.CounterVec

	// OpDuration measures wall-clock latency of a peer operation as observed
	// by the HTTP handler (includes bbolt fsync and configureDevice round-trip).
	OpDuration *prometheus.HistogramVec

	// PersistRollback fires when a configureDevice failure triggered a rollback
	// of the write-ahead bbolt record. A non-zero rate indicates kernel/WG
	// trouble and is the canonical signal for our crash-safety guarantees.
	PersistRollback *prometheus.CounterVec

	// PersistRollbackFailed fires when the rollback itself failed — bbolt now
	// holds a record that will be restored to the device on next startup.
	// This is the alert-the-on-call signal.
	PersistRollbackFailed prometheus.Counter

	// HTTPRequests counts every HTTP request the API handled, labelled by
	// method, route template (e.g. "/peers/:peerId" — never the raw path,
	// which would cardinality-bomb on UUIDs), and status_class (2xx..5xx).
	// Use for error-rate alerts and 401-burst detection (credential probing).
	HTTPRequests *prometheus.CounterVec

	// HTTPDuration measures end-to-end request latency from middleware entry
	// to handler completion, labelled by method and route template. Use for
	// p99 latency dashboards and slow-endpoint detection.
	HTTPDuration *prometheus.HistogramVec
}

// New constructs a Metrics bundle and registers it on a fresh registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		registry: reg,
		PeerOps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wgkeeper_peer_operations_total",
			Help: "Total peer lifecycle operations, labelled by op and outcome.",
		}, []string{"op", "result"}),
		OpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "wgkeeper_peer_operation_duration_seconds",
			Help: "End-to-end peer operation latency from HTTP handler entry to response.",
			// Buckets cover the realistic range: in-memory fast path (~1ms),
			// bbolt fsync (~5–50ms), configureDevice netlink (~1–100ms),
			// degenerate kernel slowness (>1s).
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"op"}),
		PersistRollback: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wgkeeper_persist_rollback_total",
			Help: "Persist rollbacks triggered by configureDevice failure during create/rotate.",
		}, []string{"op"}),
		PersistRollbackFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wgkeeper_persist_rollback_failed_total",
			Help: "Persist rollback attempts that themselves failed — bbolt holds a record that will be restored to the device on next startup. Page on this.",
		}),
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wgkeeper_http_requests_total",
			Help: "Total HTTP requests served, labelled by method, route template, and status class.",
		}, []string{"method", "path", "status_class"}),
		HTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "wgkeeper_http_request_duration_seconds",
			Help: "HTTP request latency from middleware entry to handler completion.",
			// Same buckets as peer-op duration: in-memory <1ms, bbolt fsync,
			// netlink, degenerate >1s. Letting both share the bucket grid
			// makes joining histograms in PromQL straightforward.
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"method", "path"}),
	}

	reg.MustRegister(
		m.PeerOps,
		m.OpDuration,
		m.PersistRollback,
		m.PersistRollbackFailed,
		m.HTTPRequests,
		m.HTTPDuration,
		// Standard process_* and go_* collectors give memory, GC, FDs.
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	)

	return m
}

// Registry exposes the underlying registry so the HTTP server can serve it.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// OnPersistRollback satisfies wireguard.RollbackObserver — increments the
// rollback counter for the given operation ("create" or "rotate").
func (m *Metrics) OnPersistRollback(op string) {
	m.PersistRollback.WithLabelValues(op).Inc()
}

// OnPersistRollbackFailed satisfies wireguard.RollbackObserver — increments
// the alert-grade counter when a rollback itself failed.
func (m *Metrics) OnPersistRollbackFailed() {
	m.PersistRollbackFailed.Inc()
}

// PeersSnapshot mirrors the three peer-population buckets that /stats already
// surfaces. It exists so the WireGuardService does not import prometheus
// types; the metrics package converts the snapshot to a gauge on scrape.
type PeersSnapshot struct {
	Possible int
	Issued   int
	Active   int
}

// PeersProvider reports current peer counts. WireGuardService satisfies this
// via a thin adapter.
type PeersProvider interface {
	PeersSnapshot() (PeersSnapshot, error)
}

// BindPeersProvider registers a Collector that emits the wgkeeper_peers gauge
// lazily on every scrape, reading from the provider. This avoids a background
// timer and keeps the gauge in sync with reality at scrape time.
//
// On provider error the gauge is omitted from the response (no stale value).
func (m *Metrics) BindPeersProvider(p PeersProvider) {
	desc := prometheus.NewDesc(
		"wgkeeper_peers",
		"Peer population by state (possible | issued | active).",
		[]string{"state"},
		nil,
	)
	m.registry.MustRegister(&peersCollector{provider: p, desc: desc})
}

// peersCollector drives wgkeeper_peers from a PeersProvider on every scrape.
type peersCollector struct {
	provider PeersProvider
	desc     *prometheus.Desc
}

func (c *peersCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *peersCollector) Collect(ch chan<- prometheus.Metric) {
	snap, err := c.provider.PeersSnapshot()
	if err != nil {
		// Skip emission rather than report stale or zero values; absence is a
		// cleaner signal than a misleading gauge.
		return
	}
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(snap.Possible), StatePossible)
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(snap.Issued), StateIssued)
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(snap.Active), StateActive)
}
