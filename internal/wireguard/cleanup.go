package wireguard

import (
	"context"
	"log/slog"
	"runtime/debug"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RunExpiredPeersCleanup runs a loop that periodically removes peers whose ExpiresAt is in the past.
// It exits when ctx is canceled. First run is immediate; then every interval.
func (s *WireGuardService) RunExpiredPeersCleanup(ctx context.Context, interval time.Duration) {
	s.runCleanupSafe()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runCleanupSafe()
		}
	}
}

// runCleanupSafe runs cleanupExpiredPeers and recovers any panic so the cleanup goroutine keeps running.
func (s *WireGuardService) runCleanupSafe() {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("cleanup panic recovered", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	s.cleanupExpiredPeers()
}

func (s *WireGuardService) cleanupExpiredPeers() {
	now := time.Now().UTC()

	// Collect candidates without holding any lock.
	var candidates []string
	s.store.ForEach(func(rec PeerRecord) {
		if rec.ExpiresAt != nil && !now.Before(*rec.ExpiresAt) {
			candidates = append(candidates, rec.PeerID)
		}
	})

	if len(candidates) == 0 {
		return
	}

	// Remove all expired peers in a single configureDevice call.
	deleted, err := s.doCleanupBatch(candidates, now)
	if err != nil {
		slog.Error("cleanup: batch delete expired peers", "count", len(candidates), "error", err)
	}
	if len(deleted) == 0 {
		return
	}
	if err := s.store.PersistDeleteBatch(deleted...); err != nil {
		slog.Error("cleanup: save peer store", "error", err)
	}
	for _, peerID := range deleted {
		slog.Info("expired peer removed", "peerId", peerID)
	}
}

// doCleanupBatch re-checks each candidate under s.mu, removes all still-expired
// peers from the device in one configureDevice call, and updates the store and
// usedIPs cache. Returns the list of peer IDs that were successfully removed.
//
// Re-checking under the lock prevents a race with a concurrent EnsurePeer that
// extends a peer's expiry between the ForEach snapshot and this call.
func (s *WireGuardService) doCleanupBatch(candidates []string, now time.Time) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var toRemove []PeerRecord
	for _, peerID := range candidates {
		record, ok := s.store.Get(peerID)
		if !ok {
			continue // already removed by a concurrent operation
		}
		if record.ExpiresAt == nil || now.Before(*record.ExpiresAt) {
			continue // made permanent or extended by a concurrent EnsurePeer
		}
		toRemove = append(toRemove, record)
	}
	if len(toRemove) == 0 {
		return nil, nil
	}

	// One kernel call for all removals.
	peers := make([]wgtypes.PeerConfig, len(toRemove))
	for i, rec := range toRemove {
		peers[i] = wgtypes.PeerConfig{PublicKey: rec.PublicKey, Remove: true}
	}
	if err := s.configureDevice(wgtypes.Config{Peers: peers}); err != nil {
		return nil, err
	}

	// Update store and IP cache after successful device operation.
	deleted := make([]string, 0, len(toRemove))
	for _, rec := range toRemove {
		s.store.Delete(rec.PeerID)
		for _, aip := range rec.AllowedIPs {
			delete(s.usedIPs, aip.IP.String())
			s.retractAllocHint(aip.IP)
		}
		deleted = append(deleted, rec.PeerID)
	}
	return deleted, nil
}
