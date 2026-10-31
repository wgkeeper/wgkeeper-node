package server

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
)

// apiKeyHeader is the HTTP header name for the API key (not a credential).
const apiKeyHeader = "X-API-Key" // #nosec G101

func apiKeyMiddleware(apiKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if apiKey == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "api key is not configured"})
			c.Abort()
			return
		}

		if !apiKeyMatches(c, apiKey) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func apiKeyMatches(c *gin.Context, apiKey string) bool {
	got := c.GetHeader(apiKeyHeader)
	// No early exit on length: any branch before ConstantTimeCompare leaks
	// the key length via response timing, reducing the attacker's search space.
	return subtle.ConstantTimeCompare([]byte(got), []byte(apiKey)) == 1
}
