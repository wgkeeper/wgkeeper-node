package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wgkeeper/wgkeeper-node/internal/wireguard"
)

const routerTestAPIKey = "api-key"

// TestNewRouterTrustedProxyAllowlist verifies that allowed_ips evaluates the
// real client IP from X-Forwarded-For only when the forwarding proxy is listed
// in trustedProxies. This is the prod-secure topology where Caddy runs as a
// separate (non-loopback) container.
func TestNewRouterTrustedProxyAllowlist(t *testing.T) {
	const (
		orchestratorIP = "203.0.113.7"
		caddyBridgeIP  = "172.18.0.5"
	)
	_, orchNet, _ := net.ParseCIDR(orchestratorIP + "/32")
	allowlist := []*net.IPNet{orchNet}

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/stats", nil)
		req.RemoteAddr = caddyBridgeIP + ":40000"         // arrives from Caddy, not loopback
		req.Header.Set("X-Forwarded-For", orchestratorIP) // real client per Caddy
		req.Header.Set("X-API-Key", routerTestAPIKey)
		return req
	}

	t.Run("default_loopback_only_locks_out_orchestrator", func(t *testing.T) {
		svc := wireguard.NewTestService()
		router := NewRouter(context.Background(), routerTestAPIKey, allowlist, nil, svc, nil, false)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, newReq())
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 when Caddy is not a trusted proxy, got %d", rec.Code)
		}
	})

	t.Run("trusting_caddy_lets_real_client_through", func(t *testing.T) {
		svc := wireguard.NewTestService()
		router := NewRouter(context.Background(), routerTestAPIKey, allowlist, []string{caddyBridgeIP + "/32"}, svc, nil, false)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, newReq())
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 once Caddy is trusted so XFF resolves to the orchestrator, got %d", rec.Code)
		}
	})
}

func TestNewRouterHealth(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter(context.Background(), routerTestAPIKey, nil, nil, svc, nil, false)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /healthz: got status %d", rec.Code)
	}
}

func TestNewRouterStatsWithAPIKey(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter(context.Background(), routerTestAPIKey, nil, nil, svc, nil, false)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	req.Header.Set("X-API-Key", routerTestAPIKey)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /stats with API key: got status %d", rec.Code)
	}
}

func TestNewRouterStatsWithoutAPIKey(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter(context.Background(), routerTestAPIKey, nil, nil, svc, nil, false)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /stats without API key: got status %d, want 401", rec.Code)
	}
}
