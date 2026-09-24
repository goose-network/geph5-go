package routecache

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/database"
)

func sampleRoute(port uint16) brokerproto.ExitRouteDescriptor {
	pubkey := make([]byte, 32)
	for i := range pubkey {
		pubkey[i] = 7
	}
	return brokerproto.ExitRouteDescriptor{
		ExitPubkey: pubkey,
		Exit: brokerproto.ExitDescriptor{
			C2EListen: "127.0.0.1:" + itoa(port),
			B2EListen: "127.0.0.1:" + itoa(port + 1),
			Country:   "CA",
			City:      "Toronto",
			Load:      0.1,
			Expiry:    1,
		},
		Route: brokerproto.RouteDescriptor{Kind: "tcp", TcpAddr: "127.0.0.1:" + itoa(port + 2)},
	}
}

func itoa(p uint16) string {
	if p == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for p > 0 {
		i--
		buf[i] = byte('0' + p%10)
		p /= 10
	}
	return string(buf[i:])
}

func TestCachedExitRouteRoundTripsAndOverwrites(t *testing.T) {
	db, err := database.New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	constraint := brokerproto.ExitConstraint{Kind: "country", Country: "CA"}

	initial := sampleRoute(9000)
	if err := WriteCachedExitRoute(ctx, db, constraint, initial); err != nil {
		t.Fatal(err)
	}

	cached, err := ReadCachedExitRoute(ctx, db, constraint)
	if err != nil {
		t.Fatal(err)
	}
	if cached == nil {
		t.Fatal("expected cached route, got nil")
	}
	if cached.Exit.C2EListen != "127.0.0.1:9000" {
		t.Fatalf("expected 127.0.0.1:9000, got %q", cached.Exit.C2EListen)
	}
	if len(cached.ExitPubkey) != 32 || cached.ExitPubkey[0] != 7 {
		t.Fatalf("unexpected exit pubkey: %v", cached.ExitPubkey)
	}

	updated := sampleRoute(9100)
	if err := WriteCachedExitRoute(ctx, db, constraint, updated); err != nil {
		t.Fatal(err)
	}
	cached, err = ReadCachedExitRoute(ctx, db, constraint)
	if err != nil {
		t.Fatal(err)
	}
	if cached == nil {
		t.Fatal("expected cached route after overwrite, got nil")
	}
	if cached.Exit.C2EListen != "127.0.0.1:9100" {
		t.Fatalf("expected 127.0.0.1:9100, got %q", cached.Exit.C2EListen)
	}
}

func TestCorruptCachedExitRouteIsDeleted(t *testing.T) {
	db, err := database.New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	constraint := brokerproto.ExitConstraint{Kind: "hostname", Hostname: "example.com"}

	// Build the same cache key the package uses and inject a corrupt value.
	key, err := cacheKey(constraint)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Write(ctx, key, []byte("{not-json")); err != nil {
		t.Fatal(err)
	}

	cached, err := ReadCachedExitRoute(ctx, db, constraint)
	if err != nil {
		t.Fatalf("expected nil error on corrupt row, got %v", err)
	}
	if cached != nil {
		t.Fatalf("expected nil route on corrupt row, got %v", cached)
	}

	// The corrupt row must have been deleted.
	remaining, err := db.Read(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != nil {
		t.Fatalf("expected corrupt row to be deleted, got %q", string(remaining))
	}
}

func TestReadMissingReturnsNil(t *testing.T) {
	db, err := database.New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	constraint := brokerproto.AutoConstraint()
	cached, err := ReadCachedExitRoute(ctx, db, constraint)
	if err != nil {
		t.Fatal(err)
	}
	if cached != nil {
		t.Fatalf("expected nil for missing key, got %v", cached)
	}
}

// TestCacheKeyMatchesConstraintJSON verifies the cache key is exactly
// "exit_route:" + serde-equivalent JSON of the constraint, matching the Rust
// serialize_exit_constraint behavior.
func TestCacheKeyMatchesConstraintJSON(t *testing.T) {
	constraint := brokerproto.ExitConstraint{Kind: "auto"}
	key, err := cacheKey(constraint)
	if err != nil {
		t.Fatal(err)
	}
	want := `exit_route:"auto"`
	if key != want {
		t.Fatalf("expected %q, got %q", want, key)
	}

	cj, err := serializeConstraint(constraint)
	if err != nil {
		t.Fatal(err)
	}
	var raw json.RawMessage
	if err := json.Unmarshal([]byte(cj), &raw); err != nil {
		t.Fatalf("constraint JSON is not valid JSON: %v", err)
	}
}
