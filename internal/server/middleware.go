package server

import (
	"crypto/sha256"
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
	// Compare SHA-256 digests: ConstantTimeCompare returns early when the
	// lengths differ, which would leak the key length through timing.
	got := sha256.Sum256([]byte(c.GetHeader(apiKeyHeader)))
	want := sha256.Sum256([]byte(apiKey))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}
