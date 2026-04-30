package metrics

import (
	"errors"
	"strings"
	"testing"
)

type fakeWGProvider struct {
	snap WireGuardSnapshot
	err  error
}

func (f *fakeWGProvider) WireGuardSnapshot() (WireGuardSnapshot, error) {
	return f.snap, f.err
}

func TestBindWireGuardProviderEmitsTrafficAndStale(t *testing.T) {
	m := New()
	m.BindWireGuardProvider(&fakeWGProvider{
		snap: WireGuardSnapshot{
			ReceiveBytesTotal:  1_000_000,
			TransmitBytesTotal: 500_000,
			StalePeers:         3,
		},
	})

	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	got := map[string]float64{}
	for _, mf := range mfs {
		switch mf.GetName() {
		case "wgkeeper_wireguard_rx_bytes_total",
			"wgkeeper_wireguard_tx_bytes_total",
			"wgkeeper_wireguard_stale_peers":
			for _, mm := range mf.Metric {
				if c := mm.Counter; c != nil {
					got[mf.GetName()] = c.GetValue()
				}
				if g := mm.Gauge; g != nil {
					got[mf.GetName()] = g.GetValue()
				}
			}
		}
	}

	want := map[string]float64{
		"wgkeeper_wireguard_rx_bytes_total": 1_000_000,
		"wgkeeper_wireguard_tx_bytes_total": 500_000,
		"wgkeeper_wireguard_stale_peers":    3,
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s: got %v, want %v", name, got[name], v)
		}
	}
}

func TestBindWireGuardProviderSkipsOnError(t *testing.T) {
	m := New()
	m.BindWireGuardProvider(&fakeWGProvider{err: errors.New("netlink unavailable")})

	out := gatherAsText(t, m)
	for _, name := range []string{
		"wgkeeper_wireguard_rx_bytes_total",
		"wgkeeper_wireguard_tx_bytes_total",
		"wgkeeper_wireguard_stale_peers",
	} {
		if strings.Contains(out, name) {
			t.Errorf("%s should be absent on provider error; got:\n%s", name, out)
		}
	}
}
