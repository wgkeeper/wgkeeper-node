package wireguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PeerRecord struct {
	PeerID       string
	PublicKey    wgtypes.Key
	PresharedKey wgtypes.Key // required for all peers; used when restoring peer to device
	AllowedIPs   []net.IPNet // one per address family (IPv4 and/or IPv6)
	CreatedAt    time.Time
	ExpiresAt    *time.Time // nil = permanent peer
}

// peerRecordStored is the JSON format for persistence (IPv4 and/or IPv6 in allowed_ips).
type peerRecordStored struct {
	PeerID       string     `json:"peer_id"`
	PublicKey    string     `json:"public_key"`    // base64
	PresharedKey string     `json:"preshared_key"` // required for all peers
	AllowedIPs   []string   `json:"allowed_ips"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

var peersBucket = []byte("peers")

func storedToRecord(s peerRecordStored) (PeerRecord, error) {
	if strings.TrimSpace(s.PeerID) == "" {
		return PeerRecord{}, errors.New("peer_id is required and must be non-empty")
	}
	key, err := wgtypes.ParseKey(s.PublicKey)
	if err != nil {
		return PeerRecord{}, err
	}
	nets := make([]net.IPNet, 0, len(s.AllowedIPs))
	for _, cidr := range s.AllowedIPs {
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return PeerRecord{}, err
		}
		nets = append(nets, *ipNet)
	}
	if len(nets) == 0 {
		return PeerRecord{}, errors.New("allowed_ips is required and must contain at least one valid CIDR")
	}
	if strings.TrimSpace(s.PresharedKey) == "" {
		return PeerRecord{}, errors.New("preshared_key is required and must be non-empty")
	}
	psk, err := wgtypes.ParseKey(s.PresharedKey)
	if err != nil {
		return PeerRecord{}, fmt.Errorf("preshared_key: %w", err)
	}
	return PeerRecord{
		PeerID:       s.PeerID,
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   nets,
		CreatedAt:    s.CreatedAt,
		ExpiresAt:    s.ExpiresAt,
	}, nil
}

func recordToStored(r PeerRecord) peerRecordStored {
	allowedIPs := make([]string, len(r.AllowedIPs))
	for i := range r.AllowedIPs {
		allowedIPs[i] = r.AllowedIPs[i].String()
	}
	return peerRecordStored{
		PeerID:       r.PeerID,
		PublicKey:    r.PublicKey.String(),
		PresharedKey: r.PresharedKey.String(),
		AllowedIPs:   allowedIPs,
		CreatedAt:    r.CreatedAt,
		ExpiresAt:    r.ExpiresAt,
	}
}

type PeerStore struct {
	mu         sync.RWMutex
	saveMu     sync.Mutex // serializes bbolt writes
	peers      map[string]PeerRecord
	sortedKeys []peerSortKey // maintained in (CreatedAt asc, PeerID asc) order
	db         *bolt.DB      // nil = in-memory only; open for the lifetime of the store
}

func NewPeerStore() *PeerStore {
	return &PeerStore{
		peers:      make(map[string]PeerRecord),
		sortedKeys: make([]peerSortKey, 0),
	}
}

func (s *PeerStore) Get(peerID string) (PeerRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.peers[peerID]
	return record, ok
}

func (s *PeerStore) Set(record PeerRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, exists := s.peers[record.PeerID]
	s.peers[record.PeerID] = record
	newKey := peerSortKey{record.PeerID, record.CreatedAt}
	if exists {
		// rotatePeer preserves CreatedAt, so the sort key is unchanged in the
		// common case. Only re-insert when CreatedAt actually differs.
		if !old.CreatedAt.Equal(record.CreatedAt) {
			s.removeSortedKey(peerSortKey{old.PeerID, old.CreatedAt})
			s.insertSorted(newKey)
		}
	} else {
		s.insertSorted(newKey)
	}
}

func (s *PeerStore) Delete(peerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.peers[peerID]
	if !ok {
		return
	}
	delete(s.peers, peerID)
	s.removeSortedKey(peerSortKey{rec.PeerID, rec.CreatedAt})
}

// insertSorted inserts key into sortedKeys at the correct position.
// Must be called with mu held for writing.
func (s *PeerStore) insertSorted(key peerSortKey) {
	pos := sort.Search(len(s.sortedKeys), func(i int) bool {
		ki := s.sortedKeys[i]
		if ki.createdAt.Equal(key.createdAt) {
			return ki.peerID >= key.peerID
		}
		return ki.createdAt.After(key.createdAt)
	})
	s.sortedKeys = append(s.sortedKeys, peerSortKey{})
	copy(s.sortedKeys[pos+1:], s.sortedKeys[pos:])
	s.sortedKeys[pos] = key
}

// removeSortedKey removes key from sortedKeys.
// Must be called with mu held for writing.
func (s *PeerStore) removeSortedKey(key peerSortKey) {
	pos := sort.Search(len(s.sortedKeys), func(i int) bool {
		ki := s.sortedKeys[i]
		if ki.createdAt.Equal(key.createdAt) {
			return ki.peerID >= key.peerID
		}
		return ki.createdAt.After(key.createdAt)
	})
	if pos < len(s.sortedKeys) &&
		s.sortedKeys[pos].peerID == key.peerID &&
		s.sortedKeys[pos].createdAt.Equal(key.createdAt) {
		s.sortedKeys = append(s.sortedKeys[:pos], s.sortedKeys[pos+1:]...)
	}
}

func (s *PeerStore) List() []PeerRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PeerRecord, 0, len(s.peers))
	for _, record := range s.peers {
		out = append(out, record)
	}
	return out
}

// Len returns the number of peer records without copying the store.
func (s *PeerStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

// ForEach calls fn for every peer record under a read lock.
// fn must not call any PeerStore method that acquires a write lock (Set, Delete)
// as that would deadlock.
func (s *PeerStore) ForEach(fn func(PeerRecord)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, record := range s.peers {
		fn(record)
	}
}

// peerSortKey is a lightweight tuple used to maintain sort order.
type peerSortKey struct {
	peerID    string
	createdAt time.Time
}

// ListPaginated returns a page of peer records sorted by (CreatedAt, PeerID)
// and the total number of records. offset=0 and limit=0 returns all records.
// sortedKeys is maintained incrementally so no sort is needed here.
func (s *PeerStore) ListPaginated(offset, limit int) ([]PeerRecord, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := len(s.peers)
	if offset >= total {
		return []PeerRecord{}, total
	}
	keys := s.sortedKeys[offset:]
	if limit > 0 && limit < len(keys) {
		keys = keys[:limit]
	}
	records := make([]PeerRecord, len(keys))
	for i, k := range keys {
		records[i] = s.peers[k.peerID]
	}
	return records, total
}

// OpenFile opens (or creates) the bbolt DB at path, loads all peer records into
// memory, and keeps the DB open for incremental persistence. Call Close when done.
func (s *PeerStore) OpenFile(path string) error {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return err
	}
	if err := s.loadFromDB(db); err != nil {
		_ = db.Close()
		return err
	}
	s.db = db
	return nil
}

// OpenFileIfExists is like OpenFile but returns nil without opening if the file
// does not exist.
func (s *PeerStore) OpenFileIfExists(path string) error {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return s.OpenFile(path)
}

// Close closes the underlying bbolt DB. Safe to call when no DB is open.
// Serialized with saveMu so it cannot race with concurrent persist calls.
func (s *PeerStore) Close() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// PersistPut writes a single peer record to the open DB. No-op if no DB is open.
func (s *PeerStore) PersistPut(record PeerRecord) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.db == nil {
		return nil
	}
	return s.persistPutLocked(record)
}

// PersistPutIfPresent writes a peer record to the open DB only when the peer
// is still in the in-memory store with the same public key. This prevents a
// stale write when a concurrent DeletePeer removes the peer between
// doEnsurePeer (which releases s.mu) and the caller's persist step.
// No-op if no DB is open.
func (s *PeerStore) PersistPutIfPresent(record PeerRecord) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.db == nil {
		return nil
	}
	s.mu.RLock()
	current, ok := s.peers[record.PeerID]
	s.mu.RUnlock()
	if !ok || current.PublicKey != record.PublicKey {
		return nil
	}
	return s.persistPutLocked(record)
}

func (s *PeerStore) persistPutLocked(record PeerRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(peersBucket)
		if err != nil {
			return err
		}
		data, err := json.Marshal(recordToStored(record))
		if err != nil {
			return err
		}
		return b.Put([]byte(record.PeerID), data)
	})
}

// PersistDeleteBatch removes peer records from the open DB in a single transaction.
// No-op if no DB is open or no IDs are provided.
func (s *PeerStore) PersistDeleteBatch(peerIDs ...string) error {
	if len(peerIDs) == 0 {
		return nil
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.db == nil {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(peersBucket)
		if b == nil {
			return nil
		}
		for _, id := range peerIDs {
			if err := b.Delete([]byte(id)); err != nil {
				return err
			}
		}
		return nil
	})
}

// loadFromDB replaces store contents with peer records read from db.
func (s *PeerStore) loadFromDB(db *bolt.DB) error {
	loaded := make([]PeerRecord, 0)
	seenPublicKey := make(map[wgtypes.Key]bool)
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(peersBucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var stored peerRecordStored
			if err := json.Unmarshal(v, &stored); err != nil {
				return fmt.Errorf("peer store db: decode peer %q: %w", string(k), err)
			}
			rec, err := storedToRecord(stored)
			if err != nil {
				return fmt.Errorf("peer store db: peer %q: %w", string(k), err)
			}
			if rec.PeerID != string(k) {
				return fmt.Errorf("peer store db: key/value peer_id mismatch: key=%q value=%q", string(k), rec.PeerID)
			}
			if seenPublicKey[rec.PublicKey] {
				return fmt.Errorf("peer store db: duplicate public_key for peer_id %q", rec.PeerID)
			}
			seenPublicKey[rec.PublicKey] = true
			loaded = append(loaded, rec)
			return nil
		})
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers = make(map[string]PeerRecord, len(loaded))
	for _, rec := range loaded {
		s.peers[rec.PeerID] = rec
	}
	// Rebuild the sorted index from the loaded records in one pass.
	s.sortedKeys = make([]peerSortKey, 0, len(s.peers))
	for _, rec := range s.peers {
		s.sortedKeys = append(s.sortedKeys, peerSortKey{rec.PeerID, rec.CreatedAt})
	}
	sort.Slice(s.sortedKeys, func(i, j int) bool {
		if s.sortedKeys[i].createdAt.Equal(s.sortedKeys[j].createdAt) {
			return s.sortedKeys[i].peerID < s.sortedKeys[j].peerID
		}
		return s.sortedKeys[i].createdAt.Before(s.sortedKeys[j].createdAt)
	})
	return nil
}
