package server

import (
	"fmt"
	"log/slog"

	"github.com/wgkeeper/wgkeeper-node/internal/metrics"
	"github.com/wgkeeper/wgkeeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

// loopbackProxies may set X-Forwarded-For: a reverse proxy sharing the node's
// network namespace (the Caddy setup in docker-compose.prod-secure.yml)
// connects from loopback. The client IP is only logged; no access decision
// depends on it.
var loopbackProxies = []string{"127.0.0.1", "::1"}

// NewRouter builds the API router. m is optional — pass nil when metrics are
// disabled; handlers nil-check before recording.
func NewRouter(apiKey string, wgService *wireguard.WireGuardService, m *metrics.Metrics) *gin.Engine {
	router := gin.New()
	if err := router.SetTrustedProxies(loopbackProxies); err != nil {
		panic(fmt.Sprintf("set trusted proxies: %v", err))
	}
	router.Use(requestIDMiddleware())
	router.Use(securityHeadersMiddleware())
	router.Use(bodyLimitMiddleware(MaxRequestBodySize))
	// Metrics middleware records request count + duration. Nil-safe: when
	// metrics are disabled, GinMiddleware returns a no-op so we register it
	// unconditionally.
	router.Use(m.GinMiddleware())
	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		if param.Path == "/healthz" || param.Path == "/readyz" {
			return ""
		}
		level := slog.LevelInfo
		if param.StatusCode >= 500 {
			level = slog.LevelError
		} else if param.StatusCode >= 400 {
			level = slog.LevelWarn
		}
		requestID := GetRequestIDFromContext(param.Request.Context())
		slog.Log(param.Request.Context(), level, "http request",
			"method", param.Method,
			"path", param.Path,
			"status", param.StatusCode,
			"latency", param.Latency,
			"ip", param.ClientIP,
			"request_id", requestID,
		)
		return ""
	}), gin.Recovery())
	registerRoutes(router, apiKey, wgService, m)
	return router
}

func registerRoutes(router *gin.Engine, apiKey string, wgService *wireguard.WireGuardService, m *metrics.Metrics) {
	// Liveness probe: process is up and able to serve requests.
	router.GET("/healthz", healthHandler)
	// Readiness probe: WireGuard backend is reachable and stats can be fetched.
	router.GET("/readyz", readinessHandler(wgService))
	router.GET("/stats", apiKeyMiddleware(apiKey), statsHandler(wgService))

	peers := router.Group("/peers", apiKeyMiddleware(apiKey))
	peers.GET("", listPeersHandler(wgService))
	peers.GET("/:peerId", getPeerHandler(wgService))
	peers.POST("", createPeerHandler(wgService, m))
	peers.DELETE("/:peerId", deletePeerHandler(wgService, m))
}
