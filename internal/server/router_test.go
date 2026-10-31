package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wgkeeper/wgkeeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
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

func TestRecoveryMiddlewareHidesHeaders(t *testing.T) {
	var logs strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	r := gin.New()
	r.Use(recoveryMiddleware())
	r.GET("/boom", func(*gin.Context) { panic("boom") })
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	req.Header.Set("X-API-Key", "secret-api-key-value")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want 500", rec.Code)
	}
	if strings.Contains(logs.String(), "secret-api-key-value") {
		t.Fatal("panic log must not contain request headers")
	}
	if !strings.Contains(logs.String(), "panic recovered") {
		t.Fatal("panic should be logged")
	}
}
