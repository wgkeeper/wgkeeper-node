package wireguard

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	testAllowedIP  = "10.0.0.1/32"
	testPeersFile  = "peers.db"
	testPeerIDSort = "peer-a"
)

func makeStorePeers(t *testing.T, store *PeerStore, n int) {
	t.Helper()
	base := time.Now().UTC()
	for i := 0; i < n; i++ {
		key, _ := wgtypes.GenerateKey()
		psk, _ := wgtypes.GenerateKey()
		store.Set(PeerRecord{
			PeerID:       fmt.Sprintf("peer-%d", i),
			PublicKey:    key,
			PresharedKey: psk,
			AllowedIPs:   mustParseCIDRs(t, fmt.Sprintf("10.0.%d.%d/32", i/256, i%256+1)),
			CreatedAt:    base.Add(time.Duration(i) * time.Second),
		})
	}
}

// peerIDTest = "peer-1" is defined in wireguard_test.go (same package)

func TestStoredToRecordAllowedIPs(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       peerIDTest,
		PublicKey:    key.String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{"10.0.0.3/32", "fd00::3/128"},
		CreatedAt:    time.Now().UTC(),
	}
	rec, err := storedToRecord(stored)
	if err != nil {
		t.Fatalf("storedToRecord: %v", err)
	}
	if rec.PeerID != peerIDTest {
		t.Fatalf("peer_id: got %q", rec.PeerID)
	}
	if len(rec.AllowedIPs) != 2 {
		t.Fatalf("expected 2 allowed_ips, got %d", len(rec.AllowedIPs))
	}
	if rec.AllowedIPs[0].String() != "10.0.0.3/32" || rec.AllowedIPs[1].String() != "fd00::3/128" {
		t.Fatalf("allowed_ips: got %v", rec.AllowedIPs)
	}
}

func TestSaveToFileAndLoadFromFileRoundtrip(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	rec := PeerRecord{
		PeerID:       "roundtrip",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   mustParseCIDRs(t, testAllowedIP, "fd00::1/128"),
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    nil,
	}

	dir := t.TempDir()
	path := filepath.Join(dir, testPeersFile)

	store := NewPeerStore()
	if err := store.OpenFile(path); err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	store.Set(rec)
	if err := store.PersistPut(rec); err != nil {
		t.Fatalf("PersistPut: %v", err)
	}
	store.Close()

	store2 := NewPeerStore()
	if err := store2.OpenFile(path); err != nil {
		t.Fatalf("OpenFile (reload): %v", err)
	}
	defer store2.Close()
	got, ok := store2.Get("roundtrip")
	if !ok {
		t.Fatalf("expected record after roundtrip")
	}
	if got.PublicKey != key {
		t.Fatalf("public_key changed after roundtrip")
	}
	if len(got.AllowedIPs) != 2 {
		t.Fatalf("expected 2 allowed_ips, got %d", len(got.AllowedIPs))
	}
}

func TestSaveToFileAndLoadFromFileRoundtripWithPresharedKey(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	rec := PeerRecord{
		PeerID:       "roundtrip-psk",
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   mustParseCIDRs(t, "10.0.0.2/32"),
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    nil,
	}

	dir := t.TempDir()
	path := filepath.Join(dir, testPeersFile)

	store := NewPeerStore()
	if err := store.OpenFile(path); err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	store.Set(rec)
	if err := store.PersistPut(rec); err != nil {
		t.Fatalf("PersistPut: %v", err)
	}
	store.Close()

	store2 := NewPeerStore()
	if err := store2.OpenFile(path); err != nil {
		t.Fatalf("OpenFile (reload): %v", err)
	}
	defer store2.Close()
	got, ok := store2.Get("roundtrip-psk")
	if !ok {
		t.Fatalf("expected record after roundtrip")
	}
	if got.PresharedKey != psk {
		t.Fatalf("preshared_key not preserved after roundtrip")
	}
}

func mustParseCIDRs(t *testing.T, cidrs ...string) []net.IPNet {
	t.Helper()
	out := make([]net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		out = append(out, *n)
	}
	return out
}

func TestLoadFromFileIfExistsMissingFile(t *testing.T) {
	store := NewPeerStore()
	path := filepath.Join(t.TempDir(), "nonexistent.db")
	if err := store.OpenFileIfExists(path); err != nil {
		t.Fatalf("OpenFileIfExists(missing): expected nil, got %v", err)
	}
	if len(store.List()) != 0 {
		t.Fatalf("expected empty store after missing file, got %d", len(store.List()))
	}
}

func TestLoadFromFileIfExistsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testPeersFile)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	store := NewPeerStore()
	if err := store.OpenFileIfExists(path); err != nil {
		t.Fatalf("OpenFileIfExists(empty file): expected nil, got %v", err)
	}
	defer store.Close()
}

func TestStoredToRecordEmptyPeerID(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       "  ",
		PublicKey:    key.String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{testAllowedIP},
		CreatedAt:    time.Now().UTC(),
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("storedToRecord(empty peer_id): expected error, got nil")
	}
}

func TestStoredToRecordEmptyAllowedIPs(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       peerIDTest,
		PublicKey:    key.String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{},
		CreatedAt:    time.Now().UTC(),
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("storedToRecord(empty allowed_ips): expected error, got nil")
	}
}

func TestLoadFromFileInvalidDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, testPeersFile)
	if err := os.WriteFile(path, []byte("not-a-bbolt-db"), 0o600); err != nil {
		t.Fatalf("write invalid db: %v", err)
	}
	store := NewPeerStore()
	if err := store.OpenFile(path); err == nil {
		t.Fatal("expected error for invalid bbolt file")
	}
}

func TestStoredToRecordEmptyPresharedKey(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       peerIDTest,
		PublicKey:    key.String(),
		PresharedKey: "",
		AllowedIPs:   []string{testAllowedIP},
		CreatedAt:    time.Now().UTC(),
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("storedToRecord(empty preshared_key): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "preshared_key") {
		t.Errorf("expected error about preshared_key, got: %v", err)
	}
}

func TestStoredToRecordInvalidPublicKey(t *testing.T) {
	stored := peerRecordStored{
		PeerID:     peerIDTest,
		PublicKey:  "not-a-valid-key",
		AllowedIPs: []string{testAllowedIP},
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("expected error for invalid public key")
	}
}

func TestStoredToRecordEmptyCIDRInAllowedIPs(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       peerIDTest,
		PublicKey:    key.String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{"", testAllowedIP}, // empty entry should be skipped
		CreatedAt:    time.Now().UTC(),
	}
	rec, err := storedToRecord(stored)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rec.AllowedIPs) != 1 {
		t.Fatalf("expected 1 net (empty skipped), got %d", len(rec.AllowedIPs))
	}
}

func TestStoredToRecordInvalidCIDRInAllowedIPs(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       peerIDTest,
		PublicKey:    key.String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{"not-a-cidr"},
		CreatedAt:    time.Now().UTC(),
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("expected error for invalid CIDR in allowed_ips")
	}
}

func TestStoredToRecordAllCIDRsEmpty(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	stored := peerRecordStored{
		PeerID:       peerIDTest,
		PublicKey:    key.String(),
		PresharedKey: psk.String(),
		AllowedIPs:   []string{"", ""},
		CreatedAt:    time.Now().UTC(),
	}
	_, err := storedToRecord(stored)
	if err == nil {
		t.Fatal("expected error when all allowed_ips entries are empty strings")
	}
}

func TestLoadFromFileReadError(t *testing.T) {
	store := NewPeerStore()
	err := store.OpenFile("/nonexistent-dir/peers.db")
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

func TestPeerStoreConcurrentAccess(t *testing.T) {
	store := NewPeerStore()
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	rec := PeerRecord{
		PeerID:       peerIDTest,
		PublicKey:    key,
		PresharedKey: psk,
		AllowedIPs:   mustParseCIDRs(t, testAllowedIP),
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); store.Set(rec) }()
		go func() { defer wg.Done(); store.Get(peerIDTest) }()
		go func() { defer wg.Done(); _ = store.List() }()
	}
	wg.Wait()
}

func TestSaveToFileUnwritablePath(t *testing.T) {
	store := NewPeerStore()
	err := store.OpenFile("/nonexistent-dir-xyz/peers.db")
	if err == nil {
		t.Fatal("expected error when opening unwritable path")
	}
}

func TestLoadFromFileIfExistsPermissionError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, cannot test permission errors")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, testPeersFile)
	if err := os.WriteFile(path, []byte(""), 0o000); err != nil {
		t.Fatalf("write: %v", err)
	}
	store := NewPeerStore()
	if store.OpenFileIfExists(path) == nil {
		t.Fatal("expected error for permission-denied file (non-ErrNotExist)")
	}
}

func TestLoadFromFileDuplicatePublicKey(t *testing.T) {
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	dir := t.TempDir()
	path := filepath.Join(dir, testPeersFile)
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket(peersBucket)
		if err != nil {
			return err
		}
		ra := recordToStored(PeerRecord{
			PeerID:       "a",
			PublicKey:    key,
			PresharedKey: psk,
			AllowedIPs:   mustParseCIDRs(t, testAllowedIP),
			CreatedAt:    time.Now().UTC(),
		})
		rb := recordToStored(PeerRecord{
			PeerID:       "b",
			PublicKey:    key,
			PresharedKey: psk,
			AllowedIPs:   mustParseCIDRs(t, "10.0.0.2/32"),
			CreatedAt:    time.Now().UTC(),
		})
		ba, _ := json.Marshal(ra)
		bb, _ := json.Marshal(rb)
		if err := b.Put([]byte("a"), ba); err != nil {
			return err
		}
		return b.Put([]byte("b"), bb)
	})
	if err != nil {
		t.Fatalf("prepare db: %v", err)
	}
	_ = db.Close()

	store := NewPeerStore()
	err = store.OpenFile(path)
	if err == nil {
		t.Fatal("OpenFile(duplicate public_key): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate public_key") {
		t.Errorf("expected error about duplicate public_key, got: %v", err)
	}
}

// ---------- ListPaginated ----------

func TestListPaginatedOffsetBeyondTotal(t *testing.T) {
	store := NewPeerStore()
	makeStorePeers(t, store, 3)

	// offset == total
	records, total := store.ListPaginated(3, 10)
	if total != 3 {
		t.Fatalf("expected total 3, got %d", total)
	}
	if len(records) != 0 {
		t.Fatalf("expected empty slice for offset==total, got %d records", len(records))
	}

	// offset > total
	records, total = store.ListPaginated(5, 10)
	if total != 3 {
		t.Fatalf("expected total 3, got %d", total)
	}
	if len(records) != 0 {
		t.Fatalf("expected empty slice for offset>total, got %d records", len(records))
	}
}

func TestListPaginatedLimitZeroReturnsAll(t *testing.T) {
	store := NewPeerStore()
	makeStorePeers(t, store, 5)

	records, total := store.ListPaginated(0, 0)
	if total != 5 {
		t.Fatalf("expected total 5, got %d", total)
	}
	if len(records) != 5 {
		t.Fatalf("expected 5 records for limit=0, got %d", len(records))
	}
}

// ---------- sorted index ----------

// TestPeerStoreSetUpdatesCreatedAt covers the branch in Set where an existing
// peer is updated with a different CreatedAt, triggering removeSortedKey + insertSorted.
func TestPeerStoreSetUpdatesCreatedAt(t *testing.T) {
	store := NewPeerStore()
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	t1 := time.Now().UTC()
	store.Set(PeerRecord{
		PeerID: "p1", PublicKey: key, PresharedKey: psk,
		AllowedIPs: mustParseCIDRs(t, testAllowedIP), CreatedAt: t1,
	})

	t2 := t1.Add(time.Hour)
	store.Set(PeerRecord{
		PeerID: "p1", PublicKey: key, PresharedKey: psk,
		AllowedIPs: mustParseCIDRs(t, testAllowedIP), CreatedAt: t2,
	})

	records, total := store.ListPaginated(0, 10)
	if total != 1 {
		t.Fatalf("expected total 1, got %d", total)
	}
	if !records[0].CreatedAt.Equal(t2) {
		t.Fatalf("expected updated CreatedAt %v, got %v", t2, records[0].CreatedAt)
	}
	if len(store.sortedKeys) != 1 {
		t.Fatalf("expected 1 sorted key, got %d", len(store.sortedKeys))
	}
	if !store.sortedKeys[0].createdAt.Equal(t2) {
		t.Fatalf("sortedKey.createdAt not updated: got %v", store.sortedKeys[0].createdAt)
	}
}

// TestPeerStoreDeleteNonExistent covers the early return in Delete when the
// peerID is not present in the store.
func TestPeerStoreDeleteNonExistent(t *testing.T) {
	store := NewPeerStore()
	store.Delete("ghost") // must not panic
	if len(store.sortedKeys) != 0 {
		t.Fatalf("expected empty sortedKeys, got %d", len(store.sortedKeys))
	}
}

// TestPeerStoreRemoveSortedKeyNotFound covers the guard in removeSortedKey
// when the key does not exist in the slice (no-op, must not panic).
func TestPeerStoreRemoveSortedKeyNotFound(t *testing.T) {
	store := NewPeerStore()
	key, _ := wgtypes.GenerateKey()
	psk, _ := wgtypes.GenerateKey()
	store.Set(PeerRecord{
		PeerID: "p1", PublicKey: key, PresharedKey: psk,
		AllowedIPs: mustParseCIDRs(t, testAllowedIP), CreatedAt: time.Now().UTC(),
	})
	// Call removeSortedKey with a key that is not in the slice.
	store.mu.Lock()
	store.removeSortedKey(peerSortKey{peerID: "ghost", createdAt: time.Now().UTC()})
	store.mu.Unlock()
	if len(store.sortedKeys) != 1 {
		t.Fatalf("sortedKeys should be unchanged, got len=%d", len(store.sortedKeys))
	}
}

// TestListPaginatedSortedOrder verifies that ListPaginated returns records in
// (CreatedAt, PeerID) order using the maintained sorted index.
func TestListPaginatedSortedOrder(t *testing.T) {
	store := NewPeerStore()
	base := time.Now().UTC()
	ids := []string{"peer-c", testPeerIDSort, "peer-b"}
	for i, id := range ids {
		key, _ := wgtypes.GenerateKey()
		psk, _ := wgtypes.GenerateKey()
		store.Set(PeerRecord{
			PeerID: id, PublicKey: key, PresharedKey: psk,
			AllowedIPs: mustParseCIDRs(t, fmt.Sprintf("10.0.0.%d/32", i+1)),
			CreatedAt:  base.Add(time.Duration(i) * time.Second),
		})
	}
	records, _ := store.ListPaginated(0, 10)
	want := []string{"peer-c", testPeerIDSort, "peer-b"} // insertion order = creation time order
	for i, rec := range records {
		if rec.PeerID != want[i] {
			t.Errorf("position %d: got %q, want %q", i, rec.PeerID, want[i])
		}
	}
}

// TestListPaginatedSortedOrderSameCreatedAt verifies that peers with equal
// CreatedAt are sorted by PeerID as a tiebreaker.
func TestListPaginatedSortedOrderSameCreatedAt(t *testing.T) {
	store := NewPeerStore()
	ts := time.Now().UTC()
	for i, id := range []string{"peer-z", testPeerIDSort, "peer-m"} {
		key, _ := wgtypes.GenerateKey()
		psk, _ := wgtypes.GenerateKey()
		store.Set(PeerRecord{
			PeerID: id, PublicKey: key, PresharedKey: psk,
			AllowedIPs: mustParseCIDRs(t, fmt.Sprintf("10.0.0.%d/32", i+1)),
			CreatedAt:  ts,
		})
	}
	records, _ := store.ListPaginated(0, 10)
	want := []string{testPeerIDSort, "peer-m", "peer-z"}
	for i, rec := range records {
		if rec.PeerID != want[i] {
			t.Errorf("position %d: got %q, want %q", i, rec.PeerID, want[i])
		}
	}
}

// TestLoadFromFileRebuildsSortedIndex verifies that load from DB rebuilds the
// sorted index correctly so ListPaginated works after loading from file.
func TestLoadFromFileRebuildsSortedIndex(t *testing.T) {
	key1, _ := wgtypes.GenerateKey()
	key2, _ := wgtypes.GenerateKey()
	psk1, _ := wgtypes.GenerateKey()
	psk2, _ := wgtypes.GenerateKey()
	dir := t.TempDir()
	path := filepath.Join(dir, testPeersFile)
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket(peersBucket)
		if err != nil {
			return err
		}
		rb := recordToStored(PeerRecord{
			PeerID:       "b",
			PublicKey:    key1,
			PresharedKey: psk1,
			AllowedIPs:   mustParseCIDRs(t, "10.0.0.2/32"),
			CreatedAt:    mustTime("2024-01-02T00:00:00Z"),
		})
		ra := recordToStored(PeerRecord{
			PeerID:       "a",
			PublicKey:    key2,
			PresharedKey: psk2,
			AllowedIPs:   mustParseCIDRs(t, "10.0.0.1/32"),
			CreatedAt:    mustTime("2024-01-01T00:00:00Z"),
		})
		bb, _ := json.Marshal(rb)
		ba, _ := json.Marshal(ra)
		if err := b.Put([]byte("b"), bb); err != nil {
			return err
		}
		return b.Put([]byte("a"), ba)
	})
	if err != nil {
		t.Fatalf("prepare db: %v", err)
	}
	_ = db.Close()

	store := NewPeerStore()
	if err := store.OpenFile(path); err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer store.Close()
	records, total := store.ListPaginated(0, 10)
	if total != 2 {
		t.Fatalf("expected 2 records, got %d", total)
	}
	// "a" has earlier CreatedAt so it should come first.
	if records[0].PeerID != "a" || records[1].PeerID != "b" {
		t.Errorf("expected [a b], got [%s %s]", records[0].PeerID, records[1].PeerID)
	}
}

func mustTime(ts string) time.Time {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		panic(err)
	}
	return t
}
