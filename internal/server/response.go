package server

import "github.com/wgkeeper/wgkeeper-node/internal/wireguard"

// PaginationMeta describes offset-based pagination metadata for list responses.
type PaginationMeta struct {
	Offset     int  `json:"offset"`
	Limit      int  `json:"limit"`
	TotalItems int  `json:"totalItems"`
	HasPrev    bool `json:"hasPrev"`
	HasNext    bool `json:"hasNext"`
	PrevOffset *int `json:"prevOffset,omitempty"`
	NextOffset *int `json:"nextOffset,omitempty"`
}

// Response is a generic API response envelope with a typed data payload and optional metadata.
type Response[T any] struct {
	Data T              `json:"data"`
	Meta PaginationMeta `json:"meta"`
}

// PeerListResponse is the envelope for paginated peer list responses.
type PeerListResponse = Response[[]wireguard.PeerListItem]

// HealthResponse is returned by the health check endpoint.
type HealthResponse struct {
	Status string `json:"status"`
}

// ReadinessResponse is returned by the readiness endpoint.
type ReadinessResponse struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// DeletePeerResponse is returned when a peer is successfully deleted.
type DeletePeerResponse struct {
	Status string `json:"status"`
}
