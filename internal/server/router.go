package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/wgkeeper/wgkeeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

const debugKey = "debug"

func NewRouter(ctx context.Context, apiKey string, allowedNets []*net.IPNet, wgService *wireguard.WireGuardService, debug bool) *gin.Engine {
	router := gin.New()
	// Trust only loopback proxies (e.g. Caddy on the same host).
	// This prevents X-Forwarded-For spoofing from external clients.
	if err := router.SetTrustedProxies([]string{"127.0.0.1", "::1"}); err != nil {
		panic(fmt.Sprintf("set trusted proxies: %v", err))
	}
	router.Use(requestIDMiddleware())
	router.Use(securityHeadersMiddleware())
	router.Use(bodyLimitMiddleware(MaxRequestBodySize))
	router.Use(newRateLimitMiddleware(ctx, allowedNets))
	router.Use(debugMiddleware(debug))
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
	registerRoutes(router, apiKey, allowedNets, wgService, debug)
	return router
}

func debugMiddleware(debug bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(debugKey, debug)
		c.Next()
	}
}

func registerRoutes(router *gin.Engine, apiKey string, allowedNets []*net.IPNet, wgService *wireguard.WireGuardService, debug bool) {
	// Liveness probe: process is up and able to serve requests.
	router.GET("/healthz", healthHandler)
	// Readiness probe: WireGuard backend is reachable and stats can be fetched.
	router.GET("/readyz", readinessHandler(wgService))
	router.GET("/stats", ipWhitelistMiddleware(allowedNets), apiKeyMiddleware(apiKey), statsHandler(wgService, debug))

	peers := router.Group("/peers", ipWhitelistMiddleware(allowedNets), apiKeyMiddleware(apiKey))
	peers.GET("", listPeersHandler(wgService, debug))
	peers.GET("/:peerId", getPeerHandler(wgService, debug))
	peers.POST("", createPeerHandler(wgService, debug))
	peers.DELETE("/:peerId", deletePeerHandler(wgService, debug))
}
