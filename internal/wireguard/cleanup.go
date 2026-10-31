package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// RunExpiredPeersCleanup runs the background loop: every interval it removes
// peers whose ExpiresAt is in the past and, after a timed-out device change,
// reconciles the device with the store (also right away when signalled). It
// exits when ctx is canceled. First run is immediate.
func (s *WireGuardService) RunExpiredPeersCleanup(ctx context.Context, interval time.Duration) {
	s.runCleanupSafe()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.reconcileSignal:
			s.runSafe(s.reconcileIfNeeded)
		case <-ticker.C:
			s.runSafe(s.reconcileIfNeeded)
			s.runCleanupSafe()
		}
	}
}

// runSafe runs fn and recovers a panic so the background loop keeps running.
func (s *WireGuardService) runSafe(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("background task panic recovered", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	fn()
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
	if s.rollbackObs != nil {
		s.rollbackObs.OnPeersExpired(len(deleted))
	}
	for _, d := range deleted {
		slog.Info("audit.peer_expired",
			"peerId", d.peerID,
			"publicKey", d.publicKey,
			"allowedIPs", d.allowedIPs,
		)
	}
}

// expiredPeerInfo carries audit data for a peer removed by cleanup.
type expiredPeerInfo struct {
	peerID     string
	publicKey  string
	allowedIPs []string
}

// doCleanupBatch re-checks each candidate under s.mu and removes all
// still-expired peers write-ahead, like DeletePeer: one bbolt transaction
// deletes the records, then one configureDevice call removes the device peers;
// if that call fails the records are restored. Returns the audit data for
// peers that were removed.
//
// Re-checking under the lock prevents a race with a concurrent EnsurePeer that
// extends a peer's expiry between the ForEach snapshot and this call.
func (s *WireGuardService) doCleanupBatch(candidates []string, now time.Time) ([]expiredPeerInfo, error) {
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

	ids := make([]string, len(toRemove))
	peers := make([]wgtypes.PeerConfig, len(toRemove))
	for i, rec := range toRemove {
		ids[i] = rec.PeerID
		peers[i] = wgtypes.PeerConfig{PublicKey: rec.PublicKey, Remove: true}
	}
	if err := s.store.PersistDeleteBatch(ids...); err != nil {
		return nil, fmt.Errorf(errSavePeerStoreFmt, ErrPeerStore, err)
	}
	if err := s.configureDevice(wgtypes.Config{Peers: peers}); err != nil && !s.deviceChangeUncertain(err) {
		var rbErr error
		for _, rec := range toRemove {
			rbErr = errors.Join(rbErr, s.store.PersistPut(rec))
		}
		if rbErr != nil {
			slog.Error("rollback persist after cleanup failure",
				"count", len(toRemove), "rollback_error", rbErr, "device_error", err)
		}
		s.notifyRollback(rollbackOpExpire, rbErr)
		return nil, err
	}

	s.store.DeleteBatch(ids...)
	deleted := make([]expiredPeerInfo, 0, len(toRemove))
	for _, rec := range toRemove {
		s.releaseAllocatedIPs(rec.AllowedIPs)
		ips := make([]string, len(rec.AllowedIPs))
		for i, aip := range rec.AllowedIPs {
			ips[i] = aip.String()
		}
		deleted = append(deleted, expiredPeerInfo{
			peerID:     rec.PeerID,
			publicKey:  rec.PublicKey.String(),
			allowedIPs: ips,
		})
	}
	return deleted, nil
}
