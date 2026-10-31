package server

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"

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

// routeMissKey marks a request that matched no route, so the request log can
// tell internet scanners probing random paths from errors of real API calls.
const routeMissKey = "wgkeeper.route_miss"

// requestLogLevel picks the level of the request log line: errors for 5xx,
// warnings for 4xx except a 404 for a path the API doesn't have, which is
// scanner noise and logged at info.
func requestLogLevel(status int, keys map[any]any) slog.Level {
	switch {
	case status >= http.StatusInternalServerError:
		return slog.LevelError
	case status == http.StatusNotFound && keys[routeMissKey] == true:
		return slog.LevelInfo
	case status >= http.StatusBadRequest:
		return slog.LevelWarn
	}
	return slog.LevelInfo
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
	// Metrics middleware records request count + duration. Nil-safe: when
	// metrics are disabled, GinMiddleware returns a no-op so we register it
	// unconditionally.
	router.Use(m.GinMiddleware())
	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		if param.Path == "/healthz" || param.Path == "/readyz" {
			return ""
		}
		level := requestLogLevel(param.StatusCode, param.Keys)
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
	}), recoveryMiddleware())
	// Gin still writes its default 404 body after this handler.
	router.NoRoute(func(c *gin.Context) { c.Set(routeMissKey, true) })
	registerRoutes(router, apiKey, wgService, m)
	return router
}

func registerRoutes(router *gin.Engine, apiKey string, wgService *wireguard.WireGuardService, m *metrics.Metrics) {
	// Liveness probe: process is up and able to serve requests.
	router.GET("/healthz", healthHandler)
	// Readiness probe: WireGuard backend is reachable and stats can be fetched.
	router.GET("/readyz", readinessHandler(wgService))
	router.GET("/stats", apiKeyMiddleware(apiKey), statsHandler(wgService))

	// The body limit runs after auth, so unauthenticated requests never get
	// their body read.
	peers := router.Group("/peers", apiKeyMiddleware(apiKey), bodyLimitMiddleware(MaxRequestBodySize))
	peers.GET("", listPeersHandler(wgService))
	peers.GET("/:peerId", getPeerHandler(wgService))
	peers.POST("", createPeerHandler(wgService, m))
	peers.DELETE("/:peerId", deletePeerHandler(wgService, m))
}

// recoveryMiddleware turns a handler panic into a 500 and logs it through
// slog with the request ID and stack. gin's own Recovery dumps the request
// headers in debug mode, which would put X-API-Key into the log.
func recoveryMiddleware() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, recovered any) {
		slog.Error("panic recovered",
			"request_id", GetRequestID(c),
			"method", c.Request.Method,
			"path", c.FullPath(),
			"panic", recovered,
			"stack", string(debug.Stack()),
		)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error", "code": "internal_error"})
	})
}
