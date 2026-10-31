package server

import (
	"github.com/gin-gonic/gin"
)

// securityHeadersMiddleware sets HTTP security headers on all responses. HSTS
// belongs to the reverse proxy that terminates TLS.
func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}
