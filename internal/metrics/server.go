package metrics

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

// metricsPath is hard-coded — exposing this as config invites compatibility
// drift between scrape configs and node configs for no real benefit.
const metricsPath = "/metrics"

// Hard-coded rate limit for the metrics endpoint. Prometheus scrape interval
// is typically 15–30 s; this caps a misbehaving scraper or a probe burst far
// below anything that could load the WireGuard kernel via netlink.
const (
	metricsRateLimit = rate.Limit(5)
	metricsBurst     = 10
)

// HTTP server timeouts. /metrics is a single GET that should complete in <1s.
// Tight ReadHeader/Read protect against slowloris from any TCP peer.
const (
	readHeaderTimeout = 5 * time.Second
	// maxHeaderBytes is far above what a scrape sends and far below Go's 1 MB default.
	maxHeaderBytes = 16 << 10
	readTimeout    = 10 * time.Second
	writeTimeout   = 30 * time.Second
	idleTimeout    = 60 * time.Second
)

// NewServer builds the HTTP server that serves the /metrics endpoint.
// The caller owns ListenAndServe and Shutdown.
//
// addr  — host:port to bind. Caller validates non-empty.
// token — bearer token; min length checked by config validation.
// m     — registered metrics bundle.
func NewServer(addr, token string, m *Metrics) *http.Server {
	mux := http.NewServeMux()
	mux.Handle(metricsPath, chain(
		promhttp.HandlerFor(m.Registry(), promhttp.HandlerOpts{
			// Prevent scraper-side fan-out from leaking into responses.
			ErrorHandling: promhttp.ContinueOnError,
		}),
		methodOnly(http.MethodGet),
		rateLimit(rate.NewLimiter(metricsRateLimit, metricsBurst)),
		bearerAuth(token),
	))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

// Run starts the metrics server and blocks until ctx is cancelled or
// ListenAndServe returns a fatal error. It returns nil on clean shutdown.
func Run(ctx context.Context, srv *http.Server) error {
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("metrics server shutdown error", "error", err)
		}
		return nil
	}
}

// chain wraps h in each middleware in turn, so the last one listed runs first.
// In NewServer that is bearerAuth → rateLimit → methodOnly → handler: auth
// comes before the rate limit, so unauthenticated requests can't use up the
// budget and lock the real scraper out.
func chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for _, mw := range mws {
		h = mw(h)
	}
	return h
}

// methodOnly rejects anything that is not the allowed HTTP method.
func methodOnly(method string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method {
				w.Header().Set("Allow", method)
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bearerAuth enforces a constant-time match against the configured token.
// It logs auth failures at WARN with client IP for forensic correlation.
//
// Response intentionally lacks a hint about *why* auth failed — do not help
// attackers triage which layer they are bypassing.
//
// Defence in depth: an empty configured token is rejected as a programming
// error even though config validation already forbids it. Without this guard
// a misconfiguration that bypasses validation would let any "Bearer " prefix
// through.
func bearerAuth(token string) func(http.Handler) http.Handler {
	want := []byte(token)
	wantSum := sha256.Sum256(want)
	// Rejections are logged at most once a second (burst 5), so a flood of
	// bad requests can't flood the log.
	logLimit := rate.NewLimiter(1, 5)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(want) == 0 {
				slog.Error("metrics bearer token is empty — refusing all requests")
				w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			h := r.Header.Get("Authorization")
			const prefix = "Bearer "
			got := ""
			if strings.HasPrefix(h, prefix) {
				got = h[len(prefix):]
			}
			// Compare digests: ConstantTimeCompare returns early on a length
			// mismatch, which would leak the token length.
			gotSum := sha256.Sum256([]byte(got))
			if subtle.ConstantTimeCompare(gotSum[:], wantSum[:]) != 1 {
				// client_ip is the TCP RemoteAddr (set by Go's net stack from
				// the accepted socket), not a request header — not attacker
				// controlled. slog handlers escape values regardless.
				if logLimit.Allow() {
					// #nosec G706 -- RemoteAddr-derived, escaped by slog handler.
					slog.Warn("metrics auth rejected",
						"client_ip", clientIP(r),
						"path", metricsPath,
					)
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// rateLimit returns a per-server (not per-IP) limiter. Prometheus scrape
// arrives from a single source most of the time; per-IP would be overkill and
// allow a single misconfigured scraper to drown the kernel via netlink.
func rateLimit(lim *rate.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !lim.Allow() {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts a best-effort client IP for logging. RemoteAddr is the
// only trusted source here — this server does not sit behind a trusted proxy
// and therefore must not honour X-Forwarded-For.
func clientIP(r *http.Request) string {
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
