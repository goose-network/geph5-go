package geph

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
)

// TestPerDialTierRegateAfterWarmup is the regression test for the boot-only gate
// latch: a per-exit client booted during warmup (account tier still unknown) for
// an exit the account cannot use must be re-gated on the NEXT dial once the tier
// is known, surfacing the actionable tier error instead of handing back the
// cached doomed client forever. A rejected dial must not refresh lastUse (so the
// doomed client can idle-reap rather than be kept alive by rejected traffic), and
// a usable exit booted during warmup stays usable once the tier is known.
func TestPerDialTierRegateAfterWarmup(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "geph-regate"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	started := atomic.Int64{}
	p.pinnedDialer = func(ctx context.Context, hostname string) (clientConn, error) {
		started.Add(1)
		return &fakeClient{}, nil
	}
	p.mu.Lock()
	p.exits = []exitInfo{
		{Hostname: "plus1", C2EListen: "2.2.2.2:2", PubkeyHex: "aa", AllowedLevels: []string{"Plus"}},
		{Hostname: "free1", C2EListen: "1.1.1.1:1", PubkeyHex: "bb", AllowedLevels: []string{"Plus", "Free"}},
	}
	p.mu.Unlock()
	p.client = &levelClient{isPlus: false, known: false} // warmup: tier unknown

	// A warmup dial boots and caches a client even for a Plus-only exit — the gate
	// must not misclassify a cold account (a cold Plus account read as Free).
	if _, err := p.getOrStartExitClient(context.Background(), "plus1"); err != nil {
		t.Fatalf("warmup dial to plus1 should boot: %v", err)
	}
	if started.Load() != 1 {
		t.Fatalf("warmup boot count = %d, want 1", started.Load())
	}
	p.mu.Lock()
	st := p.exitClients["plus1"]
	p.mu.Unlock()
	st.mu.Lock()
	lu := st.lastUse
	st.mu.Unlock()

	// The tier becomes known: this is a Free account, so plus1 is unusable.
	p.client = &levelClient{isPlus: false, known: true}
	_, err := p.getOrStartExitClient(context.Background(), "plus1")
	if err == nil {
		t.Fatal("after warmup a Free account dialing a Plus-only exit must be rejected, not handed the cached doomed client")
	}
	if !strings.Contains(err.Error(), "admits levels") || !strings.Contains(err.Error(), "this account is Free") {
		t.Fatalf("expected actionable tier error, got %q", err)
	}
	if started.Load() != 1 {
		t.Fatalf("rejected dial re-booted the client (count=%d), want still 1", started.Load())
	}
	st.mu.Lock()
	lu2 := st.lastUse
	st.mu.Unlock()
	if !lu2.Equal(lu) {
		t.Fatal("rejected dial refreshed lastUse; a doomed client must be allowed to idle-reap")
	}

	// A Free-admitting exit booted during warmup stays usable once the tier is known.
	if _, err := p.getOrStartExitClient(context.Background(), "free1"); err != nil {
		t.Fatalf("Free account dialing a Free-admitting exit should succeed: %v", err)
	}
}

// TestOutboundsMarksPerExitPinOnly verifies per-exit outbounds carry pin_only so
// the engine keeps them out of automatic pool/fallback rotation (a Free account
// must not round-robin onto Plus-only exits it cannot use), while the aggregate
// "geph" outbound stays auto-selectable. Every exit remains advertised so a
// pinned chain still resolves its hop.
func TestOutboundsMarksPerExitPinOnly(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "geph"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	p.mu.Lock()
	p.ready = true
	p.exits = []exitInfo{
		{Hostname: "free1", C2EListen: "1.1.1.1:1", AllowedLevels: []string{"Plus", "Free"}},
		{Hostname: "plus1", C2EListen: "2.2.2.2:2", AllowedLevels: []string{"Plus"}},
	}
	p.mu.Unlock()
	out, err := p.Outbounds(context.Background())
	if err != nil {
		t.Fatalf("Outbounds: %v", err)
	}
	var aggregate, perExit int
	for _, o := range out {
		pin, _ := o.Config["pin_only"].(bool)
		if o.Config["exit_hostname"] == nil {
			aggregate++
			if pin {
				t.Fatalf("aggregate %q must stay auto-selectable (pin_only=false)", o.ID)
			}
		} else {
			perExit++
			if !pin {
				t.Fatalf("per-exit %q must be pin_only=true (excluded from auto rotation)", o.ID)
			}
		}
	}
	if aggregate != 1 || perExit != 2 {
		t.Fatalf("got aggregate=%d perExit=%d, want 1/2", aggregate, perExit)
	}
}