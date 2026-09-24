// Package routecache implements a persistent cache of ExitRouteDescriptor keyed
// by serialized ExitConstraint, porting the geph5-client Rust crate's
// route_cache.rs module.
//
// The Rust version stores entries in a SQLite table (exit_route_cache) with the
// serialized ExitConstraint as the primary key. The Go version uses the
// internal/database key-value store, prefixing keys with "exit_route:" so the
// cache shares the misc KV namespace cleanly with other persisted state.
package routecache

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/database"
)

// keyPrefix is prepended to every cache key so the route cache does not collide
// with other users of the shared KV store.
const keyPrefix = "exit_route:"

// serializeConstraint serializes an ExitConstraint to the same JSON string that
// serde_json::to_string produces on the Rust side (the cache key). It mirrors
// serialize_exit_constraint in route_cache.rs.
func serializeConstraint(constraint brokerproto.ExitConstraint) (string, error) {
	b, err := constraint.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("routecache: serialize exit constraint: %w", err)
	}
	return string(b), nil
}

// cacheKey builds the full KV-store key for a constraint.
func cacheKey(constraint brokerproto.ExitConstraint) (string, error) {
	cj, err := serializeConstraint(constraint)
	if err != nil {
		return "", err
	}
	return keyPrefix + cj, nil
}

// WriteCachedExitRoute stores route under the cache key derived from constraint,
// overwriting any previously cached value. This mirrors write_cached_exit_route
// in route_cache.rs (INSERT ... ON CONFLICT DO UPDATE).
func WriteCachedExitRoute(ctx context.Context, db *database.Database, constraint brokerproto.ExitConstraint, route brokerproto.ExitRouteDescriptor) error {
	key, err := cacheKey(constraint)
	if err != nil {
		return err
	}
	routeJSON, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("routecache: serialize exit route: %w", err)
	}
	if err := db.Write(ctx, key, routeJSON); err != nil {
		return fmt.Errorf("routecache: write cached exit route: %w", err)
	}
	return nil
}

// ReadCachedExitRoute returns the cached ExitRouteDescriptor for constraint, or
// (nil, nil) if no entry exists. If a cached entry is present but cannot be
// JSON-decoded, the corrupt row is deleted and (nil, nil) is returned, matching
// the corrupt-row deletion behavior in read_cached_exit_route.
func ReadCachedExitRoute(ctx context.Context, db *database.Database, constraint brokerproto.ExitConstraint) (*brokerproto.ExitRouteDescriptor, error) {
	key, err := cacheKey(constraint)
	if err != nil {
		return nil, err
	}
	raw, err := db.Read(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("routecache: read cached exit route: %w", err)
	}
	if raw == nil {
		return nil, nil
	}
	var route brokerproto.ExitRouteDescriptor
	if err := json.Unmarshal(raw, &route); err != nil {
		// Cached row was corrupt: delete it and behave as if it were absent,
		// exactly like the Rust implementation.
		_ = db.Remove(ctx, key)
		return nil, nil
	}
	return &route, nil
}
