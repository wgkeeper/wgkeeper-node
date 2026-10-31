package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(securityHeadersMiddleware())
	r.GET("/ok", func(c *gin.Context) { c.Status(http.StatusOK) })

	t.Run("sets_standard_headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ok", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d", rec.Code)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("X-Content-Type-Options: got %q", rec.Header().Get("X-Content-Type-Options"))
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("X-Frame-Options: got %q", rec.Header().Get("X-Frame-Options"))
		}
		if rec.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
			t.Errorf("Referrer-Policy: got %q", rec.Header().Get("Referrer-Policy"))
		}
		if hsts := rec.Header().Get("Strict-Transport-Security"); hsts != "" {
			t.Errorf("HSTS is the reverse proxy's job, got %q", hsts)
		}
	})

}
