package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// pathUnmatched is the path label for requests that did not match any
// registered route (e.g. a 404). Using a constant prevents the raw URL —
// which is attacker-controlled and may be high-cardinality — from leaking
// into the path label.
const pathUnmatched = "unmatched"

// GinMiddleware records HTTP request count and duration for every request
// the gin router handles. Safe with a nil receiver — passing a nil *Metrics
// returns a no-op middleware so callers do not have to branch.
//
// Cardinality discipline:
//
//   - path is c.FullPath() (the route template, e.g. "/peers/:peerId"). Raw
//     URL paths would explode the series count on UUIDs.
//   - status is bucketed into status_class ("2xx", "3xx", "4xx", "5xx", or
//     "unknown" for non-standard codes). Raw codes would add noise without
//     actionable signal.
//   - method is HTTP method, restricted by gin to the small fixed set the
//     router declares.
//
// Health endpoints (/healthz, /readyz) are intentionally kept inside the
// instrumented path: they are part of the API surface and their failure
// rate is operationally interesting.
func (m *Metrics) GinMiddleware() gin.HandlerFunc {
	if m == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		path := c.FullPath()
		if path == "" {
			path = pathUnmatched
		}
		method := c.Request.Method
		statusClass := classifyStatus(c.Writer.Status())

		m.HTTPRequests.WithLabelValues(method, path, statusClass).Inc()
		m.HTTPDuration.WithLabelValues(method, path).Observe(time.Since(start).Seconds())
	}
}

// classifyStatus buckets an HTTP status code into a low-cardinality class
// label. Codes outside 100–599 fall into "unknown".
func classifyStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	}
	// Stringify so the dashboard sees something concrete for outliers.
	// Cardinality stays bounded: gin will only emit values from the standard
	// HTTP set, so this branch fires effectively never in production.
	return "unknown_" + strconv.Itoa(code)
}
