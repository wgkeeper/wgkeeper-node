package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wgkeeper/wgkeeper-node/internal/wireguard"
)

const routerTestAPIKey = "api-key"

func TestNewRouterHealth(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter(routerTestAPIKey, svc, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /healthz: got status %d", rec.Code)
	}
}

func TestNewRouterStatsWithAPIKey(t *testing.T) {
	svc := wireguard.NewTestService()
	router := NewRouter(routerTestAPIKey, svc, nil)
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
	router := NewRouter(routerTestAPIKey, svc, nil)
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /stats without API key: got status %d, want 401", rec.Code)
	}
}

func TestForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	if got := forwardedFor(req); got != "" {
		t.Errorf("no header: got %q, want empty", got)
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	if got := forwardedFor(req); got != "203.0.113.7, 10.0.0.1" {
		t.Errorf("got %q", got)
	}
	req.Header.Set("X-Forwarded-For", strings.Repeat("1", 1000))
	if got := forwardedFor(req); len(got) != maxLoggedForwardedFor {
		t.Errorf("long header must be capped at %d, got %d", maxLoggedForwardedFor, len(got))
	}
}
