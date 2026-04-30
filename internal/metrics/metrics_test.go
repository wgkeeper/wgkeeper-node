package metrics

import (
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// gatherAsText scrapes the registry and returns the exposition format text so
// tests can assert on substring presence/absence. We prefer this over
// GatherAndCompare (which is byte-exact) because we don't care about HELP/TYPE
// preamble noise here.
func gatherAsText(t *testing.T, m *Metrics) string {
	t.Helper()
	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var sb strings.Builder
	for _, mf := range mfs {
		for _, mm := range mf.Metric {
			sb.WriteString(mf.GetName())
			sb.WriteString("{")
			for i, l := range mm.Label {
				if i > 0 {
					sb.WriteString(",")
				}
				sb.WriteString(l.GetName())
				sb.WriteString("=\"")
				sb.WriteString(l.GetValue())
				sb.WriteString("\"")
			}
			sb.WriteString("}\n")
		}
	}
	return sb.String()
}

func TestNewRegistersAllMetrics(t *testing.T) {
	m := New()
	// Touch every metric so it appears in the registry output.
	m.PeerOps.WithLabelValues(OpCreate, ResultSuccess).Inc()
	m.OpDuration.WithLabelValues(OpCreate).Observe(0.01)
	m.PersistRollback.WithLabelValues(OpRotate).Inc()
	m.PersistRollbackFailed.Inc()

	got, err := testutil.GatherAndCount(m.Registry(),
		"wgkeeper_peer_operations_total",
		"wgkeeper_peer_operation_duration_seconds",
		"wgkeeper_persist_rollback_total",
		"wgkeeper_persist_rollback_failed_total",
	)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	// 1 op-counter, 1 histogram (one label set = one collector), 1 rollback, 1 rollback-failed.
	if got < 4 {
		t.Errorf("expected at least 4 series, got %d", got)
	}
}

func TestPeerOpsCounterIncrements(t *testing.T) {
	m := New()
	m.PeerOps.WithLabelValues(OpCreate, ResultSuccess).Inc()
	m.PeerOps.WithLabelValues(OpCreate, ResultSuccess).Inc()
	m.PeerOps.WithLabelValues(OpCreate, ResultErrorNoIP).Inc()

	if v := testutil.ToFloat64(m.PeerOps.WithLabelValues(OpCreate, ResultSuccess)); v != 2 {
		t.Errorf("expected 2 successes, got %v", v)
	}
	if v := testutil.ToFloat64(m.PeerOps.WithLabelValues(OpCreate, ResultErrorNoIP)); v != 1 {
		t.Errorf("expected 1 error_no_ip, got %v", v)
	}
}

func TestPersistRollbackFailedIsAlertSignal(t *testing.T) {
	m := New()
	if v := testutil.ToFloat64(m.PersistRollbackFailed); v != 0 {
		t.Errorf("expected 0 initially, got %v", v)
	}
	m.PersistRollbackFailed.Inc()
	if v := testutil.ToFloat64(m.PersistRollbackFailed); v != 1 {
		t.Errorf("expected 1 after Inc, got %v", v)
	}
}

// fakePeersProvider lets us drive the lazy peers Collector.
type fakePeersProvider struct {
	snap PeersSnapshot
	err  error
}

func (f *fakePeersProvider) PeersSnapshot() (PeersSnapshot, error) {
	return f.snap, f.err
}

func TestBindPeersProviderEmitsAllStates(t *testing.T) {
	m := New()
	m.BindPeersProvider(&fakePeersProvider{snap: PeersSnapshot{Possible: 254, Issued: 12, Active: 7}})

	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	got := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "wgkeeper_peers" {
			continue
		}
		for _, mm := range mf.Metric {
			for _, l := range mm.Label {
				if l.GetName() == "state" {
					got[l.GetValue()] = mm.Gauge.GetValue()
				}
			}
		}
	}
	for state, want := range map[string]float64{StatePossible: 254, StateIssued: 12, StateActive: 7} {
		if got[state] != want {
			t.Errorf("state=%q: got %v, want %v", state, got[state], want)
		}
	}
}

func TestBindPeersProviderSkipsOnError(t *testing.T) {
	m := New()
	m.BindPeersProvider(&fakePeersProvider{err: errors.New("device unavailable")})

	out := gatherAsText(t, m)
	// Absence is the signal — no zero value, no stale value.
	if strings.Contains(out, "wgkeeper_peers{") {
		t.Errorf("peers gauge should be absent on provider error; got:\n%s", out)
	}
}
