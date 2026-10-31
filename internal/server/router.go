package server

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/wgkeeper/wgkeeper-node/internal/metrics"
	"github.com/wgkeeper/wgkeeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

// loopbackProxies may set X-Forwarded-For for ClientIP: a proxy on the same
// host or in the same network namespace. For a proxy anywhere else, the raw
// header is logged as forwarded_for instead. Client addresses are only ever
// logged; no access decision depends on them.
var loopbackProxies = []string{"127.0.0.1", "::1"}

// maxLoggedForwardedFor caps the X-Forwarded-For value written to logs.
const maxLoggedForwardedFor = 256

// forwardedFor returns the X-Forwarded-For header for logging. It is set by
// whichever proxy is in front of the node (or by the client itself when there
// is none), so it is informational only.
func forwardedFor(r *http.Request) string {
	v := r.Header.Get("X-Forwarded-For")
	if len(v) > maxLoggedForwardedFor {
		v = v[:maxLoggedForwardedFor]
	}
	return v
}

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
			"forwarded_for", forwardedFor(param.Request),
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
