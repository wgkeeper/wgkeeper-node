package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/wgkeeper/wgkeeper-node/internal/metrics"
	"github.com/wgkeeper/wgkeeper-node/internal/wireguard"

	"github.com/gin-gonic/gin"
)

const (
	errMsgPeerIDMustBeUUIDv4 = "peerId must be uuid v4"
	maxPaginationLimit       = 1000
	defaultPaginationLimit   = 100
)

type peerRequest struct {
	PeerID          string   `json:"peerId"`
	ExpiresAt       *string  `json:"expiresAt,omitempty"`       // RFC3339; omit = permanent peer
	AddressFamilies []string `json:"addressFamilies,omitempty"` // optional: ["IPv4"], ["IPv6"], or ["IPv4","IPv6"]; omit = all node supports
}

type peerResponse struct {
	PeerID          string   `json:"peerId"`
	PublicKey       string   `json:"publicKey"`
	PrivateKey      string   `json:"privateKey"`
	PresharedKey    string   `json:"presharedKey"`
	AllowedIPs      []string `json:"allowedIPs"`
	AddressFamilies []string `json:"addressFamilies"`
}

type serverInfoResponse struct {
	PublicKey  string `json:"publicKey"`
	ListenPort int    `json:"listenPort"`
}

type createPeerResponse struct {
	Server serverInfoResponse `json:"server"`
	Peer   peerResponse       `json:"peer"`
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{Status: "ok"})
}

// readinessHandler checks whether core WireGuard dependencies are healthy enough to serve traffic.
// Currently it treats successful Stats() call as readiness signal.
func readinessHandler(wgService statsProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, err := wgService.Stats(); err != nil {
			c.JSON(http.StatusServiceUnavailable, ReadinessResponse{
				Status: "unhealthy",
				Reason: "wireguard_unavailable",
			})
			return
		}
		c.JSON(http.StatusOK, ReadinessResponse{Status: "ok"})
	}
}

func statsHandler(wgService statsProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats, err := wgService.Stats()
		if err != nil {
			writeError(c, http.StatusInternalServerError, "stats unavailable", "stats_unavailable", err)
			return
		}

		c.JSON(http.StatusOK, stats)
	}
}

func createPeerHandler(wgService wgPeerService, m *metrics.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req peerRequest
		if err := decodeStrictJSON(c.Request.Body, &req); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeError(c, http.StatusRequestEntityTooLarge, "request body too large", "body_too_large", nil)
				return
			}
			writeError(c, http.StatusBadRequest, "invalid json body", "invalid_json", err)
			return
		}
		if !IsUUIDv4(req.PeerID) {
			writeError(c, http.StatusBadRequest, errMsgPeerIDMustBeUUIDv4, "invalid_peer_id", nil)
			return
		}
		expiresAt, err := parseExpiresAt(req.ExpiresAt)
		if err != nil {
			writeError(c, http.StatusBadRequest, err.Error(), "invalid_expires_at", err)
			return
		}

		// Time the EnsurePeer call only — JSON parsing/validation is cheap and
		// not the main signal we care about.
		start := time.Now()
		info, err := wgService.EnsurePeer(req.PeerID, expiresAt, req.AddressFamilies)
		op := metrics.OpCreate
		if err == nil && info.Rotated {
			op = metrics.OpRotate
		}
		observeOp(m, op, start, err)
		if err != nil {
			status, message, reason := peerError(err)
			writeError(c, status, message, reason, err, "peerId", req.PeerID)
			return
		}

		serverPublicKey, serverListenPort, err := wgService.ServerInfo()
		if err != nil {
			writeError(c, http.StatusInternalServerError, "server public key unavailable", "server_info_unavailable", err, "peerId", req.PeerID)
			return
		}

		event := "audit.peer_created"
		if info.Rotated {
			event = "audit.peer_rotated"
		}
		slog.Info(event,
			"peerId", req.PeerID,
			"publicKey", info.PublicKey,
			"allowedIPs", info.AllowedIPs,
			"addressFamilies", info.AddressFamilies,
			"expiresAt", formatExpiresAtForLog(expiresAt),
			"client_ip", c.ClientIP(),
			"forwarded_for", forwardedFor(c.Request),
			"request_id", GetRequestIDFromContext(c.Request.Context()),
		)
		// Private and preshared keys must never be cached by proxies or browsers.
		c.Header("Cache-Control", "no-store, private, no-cache")
		c.Header("Pragma", "no-cache")
		c.JSON(http.StatusOK, createPeerResponse{
			Server: serverInfoResponse{
				PublicKey:  serverPublicKey,
				ListenPort: serverListenPort,
			},
			Peer: peerResponse{
				PeerID:          info.PeerID,
				PublicKey:       info.PublicKey,
				PrivateKey:      info.PrivateKey,
				PresharedKey:    info.PresharedKey,
				AllowedIPs:      info.AllowedIPs,
				AddressFamilies: info.AddressFamilies,
			},
		})
	}
}

func deletePeerHandler(wgService wgPeerService, m *metrics.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		peerID := c.Param("peerId")
		if !IsUUIDv4(peerID) {
			writeError(c, http.StatusBadRequest, errMsgPeerIDMustBeUUIDv4, "invalid_peer_id", nil)
			return
		}

		start := time.Now()
		allowedIPs, err := wgService.DeletePeer(peerID)
		observeOp(m, metrics.OpDelete, start, err)
		if err != nil {
			status, message, reason := peerError(err)
			writeError(c, status, message, reason, err, "peerId", peerID)
			return
		}

		slog.Info("audit.peer_deleted",
			"peerId", peerID,
			"allowedIPs", allowedIPs,
			"client_ip", c.ClientIP(),
			"forwarded_for", forwardedFor(c.Request),
			"request_id", GetRequestIDFromContext(c.Request.Context()),
		)
		c.JSON(http.StatusOK, DeletePeerResponse{Status: "ok"})
	}
}

func listPeersHandler(wgService wgPeersListProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := validatePaginationParams(c.Query("offset"), c.Query("limit")); err != nil {
			writeError(c, http.StatusBadRequest, err.Error(), "invalid_pagination", nil)
			return
		}
		offset, limit := parsePaginationParams(c.Query("offset"), c.Query("limit"))
		list, total, err := wgService.ListPeers(offset, limit)
		if err != nil {
			writeError(c, http.StatusInternalServerError, "peers list unavailable", "peers_list_unavailable", err)
			return
		}
		if list == nil {
			list = []wireguard.PeerListItem{}
		}
		hasPrev := offset > 0 && total > 0
		hasNext := offset+len(list) < total
		var prevOffset, nextOffset *int
		if hasPrev {
			prev := offset - limit
			if prev < 0 {
				prev = 0
			}
			prevOffset = &prev
		}
		if hasNext {
			next := offset + limit
			nextOffset = &next
		}

		resp := Response[[]wireguard.PeerListItem]{
			Data: list,
			Meta: PaginationMeta{
				Offset:     offset,
				Limit:      limit,
				TotalItems: total,
				HasPrev:    hasPrev,
				HasNext:    hasNext,
				PrevOffset: prevOffset,
				NextOffset: nextOffset,
			},
		}

		c.JSON(http.StatusOK, resp)
	}
}

// validatePaginationParams returns an error if offset or limit are present but invalid.
// offset must be >= 0; limit must be between 1 and maxPaginationLimit.
func validatePaginationParams(offsetStr, limitStr string) error {
	if offsetStr != "" {
		n, err := strconv.Atoi(offsetStr)
		if err != nil || n < 0 {
			return fmt.Errorf("offset must be a non-negative integer")
		}
	}
	if limitStr != "" {
		n, err := strconv.Atoi(limitStr)
		if err != nil || n <= 0 || n > maxPaginationLimit {
			return fmt.Errorf("limit must be between 1 and %d", maxPaginationLimit)
		}
	}
	return nil
}

// parsePaginationParams extracts offset and limit from pre-validated query strings.
// Returns 0 for offset if absent or invalid; defaultPaginationLimit for limit if absent.
func parsePaginationParams(offsetStr, limitStr string) (offset, limit int) {
	limit = defaultPaginationLimit
	if n, err := strconv.Atoi(offsetStr); err == nil && n >= 0 {
		offset = n
	}
	if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
		limit = n
	}
	return offset, limit
}

func getPeerHandler(wgService wgPeerDetailProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		peerID := c.Param("peerId")
		if !IsUUIDv4(peerID) {
			writeError(c, http.StatusBadRequest, errMsgPeerIDMustBeUUIDv4, "invalid_peer_id", nil)
			return
		}
		detail, err := wgService.GetPeer(peerID)
		if err != nil {
			status, message, reason := peerError(err)
			writeError(c, status, message, reason, err)
			return
		}
		c.JSON(http.StatusOK, detail)
	}
}

// formatExpiresAtForLog renders expiresAt for audit logs. nil = "permanent".
func formatExpiresAtForLog(t *time.Time) string {
	if t == nil {
		return "permanent"
	}
	return t.UTC().Format(time.RFC3339)
}

// observeOp records a peer-operation outcome to metrics. nil m disables
// metrics entirely (no allocations, no method calls).
func observeOp(m *metrics.Metrics, op string, start time.Time, err error) {
	if m == nil {
		return
	}
	m.PeerOps.WithLabelValues(op, resultLabel(err)).Inc()
	m.OpDuration.WithLabelValues(op).Observe(time.Since(start).Seconds())
}

// resultLabel maps a peer-operation error to the bounded set of result
// labels exposed to Prometheus. Unmatched errors fall through to a generic
// "internal" label so that cardinality stays fixed.
func resultLabel(err error) string {
	if err == nil {
		return metrics.ResultSuccess
	}
	switch {
	case errors.Is(err, wireguard.ErrNoAvailableIP):
		return metrics.ResultErrorNoIP
	case errors.Is(err, wireguard.ErrUnsupportedAddressFamily):
		return metrics.ResultErrorUnsupportedFam
	case errors.Is(err, wireguard.ErrPeerNotFound):
		return metrics.ResultErrorNotFound
	case errors.Is(err, wireguard.ErrInvalidAddressFamily):
		return metrics.ResultErrorUnsupportedFam
	case errors.Is(err, wireguard.ErrPeerStore):
		return metrics.ResultErrorPersist
	}
	return metrics.ResultErrorInternal
}

// parseExpiresAt parses optional RFC3339 date. If nil or empty, returns (nil, nil).
// If provided, must be in the future; otherwise returns error.
func parseExpiresAt(s *string) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil, errors.New("expiresAt must be RFC3339")
	}
	utc := t.UTC()
	now := time.Now().UTC()
	if !utc.After(now) {
		return nil, errors.New("expiresAt must be in the future")
	}
	return &utc, nil
}

func peerError(err error) (int, string, string) {
	if errors.Is(err, wireguard.ErrPeerNotFound) {
		return http.StatusNotFound, "peer not found", "peer_not_found"
	}
	if errors.Is(err, wireguard.ErrNoAvailableIP) {
		return http.StatusConflict, "no available ip addresses", "no_available_ip"
	}
	if errors.Is(err, wireguard.ErrPeerExpired) {
		return http.StatusConflict, "peer has expired; pass a future expiresAt to renew it", "peer_expired"
	}
	if errors.Is(err, wireguard.ErrInvalidAddressFamily) {
		return http.StatusBadRequest, "addressFamilies may only contain IPv4 and IPv6, each at most once", "invalid_address_family"
	}
	if errors.Is(err, wireguard.ErrUnsupportedAddressFamily) {
		return http.StatusBadRequest, "requested address family is not supported by this node", "unsupported_address_family"
	}

	return http.StatusInternalServerError, "wireguard operation failed", "wireguard_error"
}

// decodeStrictJSON decodes exactly one JSON object into v. Unknown fields and
// trailing data are errors: a misspelled field such as "expires_at" would
// otherwise be dropped and, for expiresAt, issue a peer that never expires.
func decodeStrictJSON(body io.Reader, v any) error {
	if body == nil {
		return errors.New("empty body")
	}
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return err
		}
		return errors.New("unexpected data after the JSON object")
	}
	return nil
}

// writeError sends a JSON error. Internal details never reach the client:
// when err is set it is logged with the request ID and attrs instead, so the
// response's X-Request-Id leads to the full error in the node's log.
func writeError(c *gin.Context, status int, message, code string, err error, attrs ...any) {
	if err != nil {
		level := slog.LevelWarn
		if status >= http.StatusInternalServerError {
			level = slog.LevelError
		}
		args := append([]any{
			"request_id", GetRequestID(c),
			"method", c.Request.Method,
			"path", c.FullPath(),
			"status", status,
			"code", code,
			"client_ip", c.ClientIP(),
			"forwarded_for", forwardedFor(c.Request),
			"error", err,
		}, attrs...)
		slog.Log(c.Request.Context(), level, "request failed", args...)
	}
	c.JSON(status, gin.H{"error": message, "code": code})
}

type wgPeerService interface {
	EnsurePeer(peerID string, expiresAt *time.Time, addressFamilies []string) (wireguard.PeerInfo, error)
	// DeletePeer returns the AllowedIPs that were freed (for audit logging).
	DeletePeer(string) ([]string, error)
	ServerInfo() (string, int, error)
}

// statsProvider provides WireGuard stats (single-method interface naming).
type statsProvider interface {
	Stats() (wireguard.Stats, error)
}

type wgPeersListProvider interface {
	ListPeers(offset, limit int) ([]wireguard.PeerListItem, int, error)
}

type wgPeerDetailProvider interface {
	GetPeer(string) (*wireguard.PeerDetail, error)
}
