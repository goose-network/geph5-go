// Package database implements a simple persistent key-value store that ports
// the Rust geph5-client database module (binaries/geph5-client/src/database.rs).
//
// The Rust version uses sqlx with a SQLite table `misc(key TEXT PRIMARY KEY,
// value BLOB)`. To avoid pulling in a CGO SQLite dependency, this package
// implements an equivalent store backed by a single JSON file (a map from
// string keys to base64-encoded values) that is rewritten atomically on every
// mutation. When no path is configured (New("")), the store lives entirely in
// memory for the lifetime of the process.
//
// The four operations mirror the Rust functions exactly:
//
//   - Write: upserts a key/value pair, then broadcasts a wake-up to all
//     blocked readers.
//   - Read: returns the value for a key, or (nil, nil) if the key is absent.
//   - ReadOrWait: blocks until the key exists, then returns its value. It
//     registers a listener BEFORE reading to avoid the lost-wakeup race in
//     which a writer inserts the key between the read and the listener
//     registration (this is the same pattern as the Rust db_read_or_wait,
//     which calls ctx.get(EVENT).listen() before db_read).
//   - Remove: deletes a key, then broadcasts a wake-up.
//
// All methods are safe for concurrent use. The broadcast signaling uses a
// sync.Cond, which wakes every waiting goroutine on each notify; readers
// re-check the store and either return or go back to waiting, matching the
// event_listener::Event::notify(usize::MAX) semantics in Rust.
package database

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Database is a persistent (or in-memory) key-value store with broadcast
// wake-up support for ReadOrWait.
type Database struct {
	mu   sync.Mutex
	cond *sync.Cond

	// store holds the key/value pairs. Values are stored as raw []byte; the
	// on-disk encoding base64-encodes them into JSON strings.
	store map[string][]byte

	// path is the file backing the store. If empty, the store is in-memory
	// only and never persisted to disk.
	path string
}

// New creates a Database backed by the file at path. If path is empty, the
// database is in-memory only (still persistent for the process lifetime). If
// the file exists, its contents are loaded; if it does not exist, an empty
// store is created and the file is written on the first mutation.
func New(path string) (*Database, error) {
	db := &Database{
		store: make(map[string][]byte),
		path:  path,
	}
	db.cond = sync.NewCond(&db.mu)

	if path != "" {
		if err := db.load(); err != nil {
			return nil, fmt.Errorf("database: load %s: %w", path, err)
		}
	}
	return db, nil
}

// load reads the on-disk JSON map into the store. A missing file is treated
// as an empty store. The caller is responsible for holding db.mu (load does
// not acquire it itself so New can call it before the first external use).
func (db *Database) load() error {
	if db.path == "" {
		return nil
	}
	data, err := os.ReadFile(db.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		val, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return fmt.Errorf("decode value for key %q: %w", k, err)
		}
		db.store[k] = val
	}
	return nil
}

// flush writes the current store to disk atomically. The caller MUST hold
// db.mu.
func (db *Database) flush() error {
	if db.path == "" {
		return nil
	}
	raw := make(map[string]string, len(db.store))
	for k, v := range db.store {
		raw[k] = base64.StdEncoding.EncodeToString(v)
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	dir := filepath.Dir(db.path)
	if dir == "" || dir == "." {
		dir = "."
	}
	// Ensure the parent directory exists.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".geph5-db-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if rename succeeded
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, db.path); err != nil {
		return err
	}
	return nil
}

// Write persists key=value, overwriting any existing value, and broadcasts a
// wake-up to all blocked ReadOrWait callers. It returns nil on success. This
// mirrors the Rust db_write function (INSERT ... ON CONFLICT DO UPDATE, then
// EVENT.notify(usize::MAX)).
func (db *Database) Write(ctx context.Context, key string, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	db.mu.Lock()
	defer db.mu.Unlock()

	// Copy the value so later mutation of the caller's slice cannot corrupt
	// the stored data.
	stored := make([]byte, len(value))
	copy(stored, value)
	db.store[key] = stored

	if err := db.flush(); err != nil {
		return err
	}
	// Broadcast to all waiters (matches event_listener::Event::notify(usize::MAX)).
	db.cond.Broadcast()
	return nil
}

// Read returns the value for key, or (nil, nil) if the key is absent. The
// returned slice is a copy of the stored data; callers may mutate it freely.
// This mirrors the Rust db_read function's Option<Vec<u8>> return.
func (db *Database) Read(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	v, ok := db.store[key]
	if !ok {
		return nil, nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

// ReadOrWait blocks until key exists, then returns its value. It repeatedly
// registers a wait (via cond.Wait) BEFORE re-reading the store, so a Write
// that lands between the read and the wait is not lost: the next loop
// iteration observes the new value and returns. This mirrors the Rust
// db_read_or_wait, which calls ctx.get(EVENT).listen() before db_read.
//
// If ctx is canceled before the key appears, ReadOrWait returns ctx.Err().
// Because sync.Cond does not integrate with context, a background goroutine
// broadcasts on context cancellation to ensure the waiter unblocks promptly.
func (db *Database) ReadOrWait(ctx context.Context, key string) ([]byte, error) {
	// Fast path: key already present.
	db.mu.Lock()
	if v, ok := db.store[key]; ok {
		out := make([]byte, len(v))
		copy(out, v)
		db.mu.Unlock()
		return out, nil
	}

	// If the context is already done, return immediately.
	if err := ctx.Err(); err != nil {
		db.mu.Unlock()
		return nil, err
	}

	// Arrange to wake this waiter if the context is canceled while we are
	// blocked in cond.Wait. sync.Cond has no context support, so we spawn a
	// goroutine that broadcasts on cancellation; the waiter loop then
	// observes ctx.Err() and returns.
	ctxDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			db.mu.Lock()
			db.cond.Broadcast()
			db.mu.Unlock()
		case <-ctxDone:
		}
	}()
	defer close(ctxDone)

	for {
		// Register the wait (cond.Wait releases the lock, waits, then
		// reacquires it) BEFORE re-reading, so we cannot miss a write that
		// happens between the read and the wait.
		db.cond.Wait()
		if v, ok := db.store[key]; ok {
			out := make([]byte, len(v))
			copy(out, v)
			db.mu.Unlock()
			return out, nil
		}
		if err := ctx.Err(); err != nil {
			db.mu.Unlock()
			return nil, err
		}
	}
}

// Remove deletes key from the store (a no-op if the key is absent) and
// broadcasts a wake-up to all blocked ReadOrWait callers. This mirrors the
// Rust db_remove function.
func (db *Database) Remove(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	delete(db.store, key)
	if err := db.flush(); err != nil {
		return err
	}
	db.cond.Broadcast()
	return nil
}

// Keys returns a snapshot of all keys currently in the store. The returned
// slice is a copy and is sorted lexicographically so callers can enumerate
// entries in a deterministic order (e.g. to model a SQL ORDER BY over a
// prefix-keyed "table"). This has no Rust counterpart (sqlx queries express
// enumeration directly) but is needed by Go packages that emulate SQL tables
// on top of the KV store, such as the bw_tokens table in internal/bwtoken.
func (db *Database) Keys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	keys := make([]string, 0, len(db.store))
	for k := range db.store {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}
