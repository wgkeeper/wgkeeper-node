package wireguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ipv4RoutesHeader = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"

func writeRoutes(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write routes: %v", err)
	}
	return path
}

func TestParseIPv4DefaultRoute(t *testing.T) {
	cases := map[string]struct {
		routes string
		want   string
	}{
		"single_default": {
			routes: "ens3\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
				"ens3\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n",
			want: "ens3",
		},
		"lowest_metric_wins": {
			routes: "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
		"down_route_ignored": {
			routes: "eth1\t00000000\t0101A8C0\t0002\t0\t0\t0\t00000000\t0\t0\t0\n" +
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			want: "eth0",
		},
		"no_default": {
			routes: "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n",
			want:   "",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseIPv4DefaultRoute(strings.NewReader(ipv4RoutesHeader + tc.routes))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseIPv6DefaultRoute(t *testing.T) {
	routes := "" +
		// Unreachable default on lo (RTF_REJECT) must be skipped.
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n" +
		"fd000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n" +
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n"
	got, err := parseIPv6DefaultRoute(strings.NewReader(routes))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "eth0" {
		t.Fatalf("got %q, want eth0", got)
	}
}

func TestDefaultRouteInterface(t *testing.T) {
	ipv6Only := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     ens5\n"

	t.Run("prefers_ipv4", func(t *testing.T) {
		v4 := writeRoutes(t, "route", ipv4RoutesHeader+"ens3\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
		v6 := writeRoutes(t, "ipv6_route", ipv6Only)
		got, err := defaultRouteInterface(v4, v6)
		if err != nil || got != "ens3" {
			t.Fatalf("got %q, %v; want ens3", got, err)
		}
	})

	t.Run("falls_back_to_ipv6", func(t *testing.T) {
		v4 := writeRoutes(t, "route", ipv4RoutesHeader)
		v6 := writeRoutes(t, "ipv6_route", ipv6Only)
		got, err := defaultRouteInterface(v4, v6)
		if err != nil || got != "ens5" {
			t.Fatalf("got %q, %v; want ens5", got, err)
		}
	})

	t.Run("no_route_is_an_error", func(t *testing.T) {
		v4 := writeRoutes(t, "route", ipv4RoutesHeader)
		missing := filepath.Join(t.TempDir(), "absent")
		if _, err := defaultRouteInterface(v4, missing); err == nil {
			t.Fatal("expected an error when no default route exists")
		}
	})

	t.Run("unsafe_name_rejected", func(t *testing.T) {
		v4 := writeRoutes(t, "route", ipv4RoutesHeader+"bad;if\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
		if _, err := defaultRouteInterface(v4, filepath.Join(t.TempDir(), "absent")); err == nil {
			t.Fatal("expected an error for an interface name unsafe for iptables rules")
		}
	})
}

func TestResolveWANInterfaceConfiguredWins(t *testing.T) {
	got, err := resolveWANInterface("eth9")
	if err != nil || got != "eth9" {
		t.Fatalf("got %q, %v; want eth9", got, err)
	}
}
