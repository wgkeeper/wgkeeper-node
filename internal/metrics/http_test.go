package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func init() { gin.SetMode(gin.TestMode) }

// newRouter wires the metrics middleware in front of a few representative
// routes that mirror the production API surface (a templated path, a fixed
// path, an error path).
func newRouter(m *Metrics) *gin.Engine {
	r := gin.New()
	r.Use(m.GinMiddleware())
	r.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/peers/:peerId", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.POST("/boom", func(c *gin.Context) { c.Status(http.StatusInternalServerError) })
	return r
}

func TestGinMiddlewareRecordsRequest(t *testing.T) {
	m := New()
	r := newRouter(m)

	req := httptest.NewRequest(http.MethodGet, "/peers/abc-123", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if got := testutil.ToFloat64(m.HTTPRequests.WithLabelValues("GET", "/peers/:peerId", "2xx")); got != 1 {
		t.Errorf("expected 1 request counted under route template, got %v", got)
	}
}

func TestGinMiddlewareUsesRouteTemplateNotRawPath(t *testing.T) {
	// Two requests to the same template MUST collapse into one series — that
	// is the cardinality contract of the path label.
	m := New()
	r := newRouter(m)

	for _, id := range []string{"alice", "bob", "carol"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/peers/"+id, nil))
	}

	if got := testutil.ToFloat64(m.HTTPRequests.WithLabelValues("GET", "/peers/:peerId", "2xx")); got != 3 {
		t.Errorf("expected 3 requests on template, got %v", got)
	}

	// Sanity: raw paths must not appear as labels.
	mfs, _ := m.Registry().Gather()
	for _, mf := range mfs {
		if mf.GetName() != "wgkeeper_http_requests_total" {
			continue
		}
		for _, mm := range mf.Metric {
			for _, l := range mm.Label {
				if l.GetName() == "path" && strings.Contains(l.GetValue(), "alice") {
					t.Errorf("raw path leaked into label: %q", l.GetValue())
				}
			}
		}
	}
}

func TestGinMiddlewareLabelsUnmatchedPath(t *testing.T) {
	m := New()
	r := newRouter(m)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/no/such/route", nil))

	if got := testutil.ToFloat64(m.HTTPRequests.WithLabelValues("GET", pathUnmatched, "4xx")); got != 1 {
		t.Errorf("expected unmatched path counted under %q, got %v", pathUnmatched, got)
	}
}

func TestGinMiddlewareCountsErrorClass(t *testing.T) {
	m := New()
	r := newRouter(m)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/boom", nil))

	if got := testutil.ToFloat64(m.HTTPRequests.WithLabelValues("POST", "/boom", "5xx")); got != 1 {
		t.Errorf("expected 5xx classification, got %v", got)
	}
}

func TestGinMiddlewareObservesDuration(t *testing.T) {
	m := New()
	r := newRouter(m)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	count := testutil.CollectAndCount(m.HTTPDuration, "wgkeeper_http_request_duration_seconds")
	if count == 0 {
		t.Error("expected at least one duration observation")
	}
}

func TestGinMiddlewareNilReceiverIsNoOp(t *testing.T) {
	// When metrics are disabled, callers pass nil. The middleware must still
	// be safe to register and must not panic on use.
	var m *Metrics
	r := gin.New()
	r.Use(m.GinMiddleware())
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with nil metrics, got %d", rec.Code)
	}
}

func TestClassifyStatus(t *testing.T) {
	cases := map[int]string{
		200: "2xx", 201: "2xx", 299: "2xx",
		301: "3xx",
		400: "4xx", 401: "4xx", 404: "4xx",
		500: "5xx", 503: "5xx",
		0:   "unknown_0",
		700: "unknown_700",
	}
	for code, want := range cases {
		if got := classifyStatus(code); got != want {
			t.Errorf("classifyStatus(%d): got %q, want %q", code, got, want)
		}
	}
}
