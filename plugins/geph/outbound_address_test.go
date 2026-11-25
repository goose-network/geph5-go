package geph

import "testing"

// TestAggregateAddressEmpty guards the dial-reachability latch fix. The
// aggregate (auto) outbound must report an empty Address so the engine's dial
// sweep skips it: a pseudo-URI like "geph://<tunnel>" is not a dialable
// host:port, so probing it would fail deterministically and latch a permanent
// "unreachable" verdict. With per-exit outbounds pin-only, the aggregate is
// geph's sole auto route, so that verdict would drop geph from every
// auto-selected first hop with no recovery. An empty address means no verdict
// is measured and reachableCandidates fails open.
//
// A pinned per-exit outbound still reports its real c2e host:port, so a chain's
// previous hop can tunnel toward it and the sweep can measure its reachability.
func TestAggregateAddressEmpty(t *testing.T) {
	agg := &outbound{id: "geph", tunnel: "geph"}
	if got := agg.Address(); got != "" {
		t.Fatalf("aggregate Address() = %q, want \"\" (skip dial sweep, fail open)", got)
	}
	pe := &outbound{id: "geph-exit1", tunnel: "geph", exitHostname: "exit1", address: "1.2.3.4:443"}
	if got := pe.Address(); got != "1.2.3.4:443" {
		t.Fatalf("per-exit Address() = %q, want the c2e host:port", got)
	}
}
