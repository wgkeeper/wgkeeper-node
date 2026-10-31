package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

const (
	middlewareTestStatusOKFmt  = "status: got %d, want 200"
	middlewareTestStatus401Fmt = "status: got %d, want 401"
)

func TestAPIKeyMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("empty_api_key_returns_500", func(t *testing.T) {
		r := gin.New()
		r.GET("/", apiKeyMiddleware(""), func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status: got %d, want 500", rec.Code)
		}
	})

	t.Run("wrong_key_returns_401", func(t *testing.T) {
		r := gin.New()
		r.GET("/", apiKeyMiddleware("secret"), func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(apiKeyHeader, "wrong")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf(middlewareTestStatus401Fmt, rec.Code)
		}
	})

	t.Run("correct_key_calls_next", func(t *testing.T) {
		r := gin.New()
		r.GET("/", apiKeyMiddleware("secret"), func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(apiKeyHeader, "secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf(middlewareTestStatusOKFmt, rec.Code)
		}
	})

	t.Run("wrong_key_length_returns_401", func(t *testing.T) {
		r := gin.New()
		r.GET("/", apiKeyMiddleware("ab"), func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(apiKeyHeader, "a")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf(middlewareTestStatus401Fmt, rec.Code)
		}
	})
}
