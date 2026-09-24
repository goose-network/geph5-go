package database

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWriteReadRemove(t *testing.T) {
	db, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Absent key returns nil, nil.
	got, err := db.Read(ctx, "missing")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil for missing key, got %v", got)
	}

	// Write then read.
	if err := db.Write(ctx, "k1", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	got, err = db.Read(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("v1")) {
		t.Fatalf("expected v1, got %q", got)
	}

	// Overwrite.
	if err := db.Write(ctx, "k1", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	got, err = db.Read(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("v2")) {
		t.Fatalf("expected v2, got %q", got)
	}

	// Remove.
	if err := db.Remove(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	got, err = db.Read(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil after remove, got %v", got)
	}
}

func TestReadOrWaitBlocksThenReturns(t *testing.T) {
	db, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	var (
		wg      sync.WaitGroup
		got     []byte
		gotErr  error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, gotErr = db.ReadOrWait(ctx, "conn_token_42")
	}()

	// Give the waiter a moment to register.
	time.Sleep(50 * time.Millisecond)

	if err := db.Write(ctx, "conn_token_42", []byte("token-bytes")); err != nil {
		t.Fatal(err)
	}

	wg.Wait()
	if gotErr != nil {
		t.Fatal(gotErr)
	}
	if !bytes.Equal(got, []byte("token-bytes")) {
		t.Fatalf("expected token-bytes, got %q", got)
	}
}

func TestReadOrWaitAlreadyPresent(t *testing.T) {
	db, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := db.Write(ctx, "present", []byte("yes")); err != nil {
		t.Fatal(err)
	}
	got, err := db.ReadOrWait(ctx, "present")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("yes")) {
		t.Fatalf("expected yes, got %q", got)
	}
}

func TestReadOrWaitContextCancel(t *testing.T) {
	db, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	got, err := db.ReadOrWait(ctx, "never-appears")
	if err != context.DeadlineExceeded {
		t.Fatalf("expected DeadlineExceeded, got %v (val=%q)", err, got)
	}
	if got != nil {
		t.Fatalf("expected nil value on cancel, got %v", got)
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.json")

	db1, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := db1.Write(ctx, "persisted", []byte("hello")); err != nil {
		t.Fatal(err)
	}

	// Reopen from the same path.
	db2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := db2.Read(ctx, "persisted")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("expected persisted hello, got %q", got)
	}

	// Verify the file exists on disk.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected db file to exist: %v", err)
	}
}

func TestConcurrentWriters(t *testing.T) {
	db, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "k"
			if err := db.Write(ctx, key, []byte{byte(i)}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	got, err := db.Read(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1-byte value, got %v", got)
	}
}
