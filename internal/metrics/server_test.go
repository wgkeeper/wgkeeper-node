package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "0123456789abcdef0123456789abcdef" // 32 chars, fits the config minimum

// newTestHandler builds a handler matching production middleware order so we
// can hit it via httptest without binding a real port.
func newTestHandler(t *testing.T, m *Metrics, token string) http.Handler {
	t.Helper()
	srv := NewServer("127.0.0.1:0", token, m)
	return srv.Handler
}

func TestServerRejectsRequestWithoutBearer(t *testing.T) {
	m := New()
	h := newTestHandler(t, m, testToken)

	req := httptest.NewRequest(http.MethodGet, metricsPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header on 401")
	}
}

func TestServerRejectsWrongBearer(t *testing.T) {
	m := New()
	h := newTestHandler(t, m, testToken)

	req := httptest.NewRequest(http.MethodGet, metricsPath, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestServerAcceptsCorrectBearer(t *testing.T) {
	m := New()
	m.PeerOps.WithLabelValues(OpCreate, ResultSuccess).Inc()
	h := newTestHandler(t, m, testToken)

	req := httptest.NewRequest(http.MethodGet, metricsPath, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "wgkeeper_peer_operations_total") {
		t.Errorf("expected metric in response, got:\n%s", string(body))
	}
}

func TestServerRejectsNonGetMethod(t *testing.T) {
	m := New()
	h := newTestHandler(t, m, testToken)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, metricsPath, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("method=%s: expected 405, got %d", method, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodGet {
			t.Errorf("method=%s: expected Allow: GET, got %q", method, got)
		}
	}
}

func TestServerRateLimitTrips(t *testing.T) {
	m := New()
	h := newTestHandler(t, m, testToken)

	authedReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, metricsPath, nil)
		r.Header.Set("Authorization", "Bearer "+testToken)
		return r
	}

	// Burst is 10. Hammer 30 requests in quick succession; some must 429.
	got429 := false
	for range 30 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authedReq())
		if rec.Code == http.StatusTooManyRequests {
			got429 = true
			if rec.Header().Get("Retry-After") == "" {
				t.Error("expected Retry-After header on 429")
			}
			break
		}
	}
	if !got429 {
		t.Error("expected at least one 429 within 30 rapid requests (burst=10, rate=5/s)")
	}
}

// Empty-token defence-in-depth: even if config validation is bypassed, an
// empty configured token must reject every request.
func TestServerEmptyTokenRejectsAll(t *testing.T) {
	m := New()
	h := newTestHandler(t, m, "")

	for _, authHeader := range []string{"", "Bearer ", "Bearer anything"} {
		req := httptest.NewRequest(http.MethodGet, metricsPath, nil)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("auth=%q: expected 401 with empty token, got %d", authHeader, rec.Code)
		}
	}
}
