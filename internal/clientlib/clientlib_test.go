package clientlib

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goose-network/geph5-go/internal/brokerproto"
	"github.com/goose-network/geph5-go/internal/config"
)

// dialRecorder is a thread-safe record of dialed "network address" pairs.
type dialRecorder struct {
	mu  sync.Mutex
	rec []string
}

func (r *dialRecorder) record(network, address string) {
	r.mu.Lock()
	r.rec = append(r.rec, network+" "+address)
	r.mu.Unlock()
}

func (r *dialRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.rec...)
}

// recordingDialer records every dial and then fails it: the client keeps
// retrying in the background, but no connection (and no blocked goroutine)
// outlives the test.
func recordingDialer(rec *dialRecorder) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		rec.record(network, address)
		return nil, errors.New("recordingDialer: not really dialing")
	}
}

// waitForDial polls until rec holds at least one dial or the deadline passes.
func waitForDial(rec *dialRecorder, timeout time.Duration) []string {
	deadline := time.Now().Add(timeout)
	for len(rec.recorded()) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	return rec.recorded()
}

// TestStackDialerCarriesExitDials verifies the data-path slot: with both
// dialers set, the route tree's raw TCP to the exit (a direct constraint, so
// no broker is involved) rides StackDialer, and the broker dialer is untouched.
func TestStackDialerCarriesExitDials(t *testing.T) {
	stackRec, brokerRec := &dialRecorder{}, &dialRecorder{}
	c, err := Start(context.Background(), Options{
		NoListener:   true,
		StackDialer:  recordingDialer(stackRec),
		BrokerDialer: recordingDialer(brokerRec),
		Config: &config.Config{
			ExitConstraint: brokerproto.ExitConstraint{
				Kind:   "direct",
				Direct: "127.0.0.1:1/" + strings.Repeat("aa", 32),
			},
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Close()

	// With no broker, the auth manager never marks account status checked, so
	// the session's first GetConnectToken waits out accountStatusWaitTimeout
	// (~10s) before the exit dial happens. The budget must clear that gate
	// with margin for -race scheduling, not merely equal it.
	got := waitForDial(stackRec, 30*time.Second)
	if len(got) == 0 {
		t.Fatal("the exit dial never rode StackDialer")
	}
	for _, d := range got {
		if d != "tcp 127.0.0.1:1" {
			t.Fatalf("unexpected data-path dial %q, want the exit address only", d)
		}
	}
	if got := brokerRec.recorded(); len(got) != 0 {
		t.Fatalf("BrokerDialer carried exit dials: %v", got)
	}
}

// TestBrokerDialerCarriesBrokerFetches verifies the control-plane slot: with
// both dialers set, the broker transport's raw TCP (the auth loop's
// get_auth_token and the session manager's get_exit_route) rides BrokerDialer,
// while StackDialer stays untouched — no route ever arrives, so no exit dial
// can happen.
func TestBrokerDialerCarriesBrokerFetches(t *testing.T) {
	stackRec, brokerRec := &dialRecorder{}, &dialRecorder{}
	c, err := Start(context.Background(), Options{
		NoListener:   true,
		StackDialer:  recordingDialer(stackRec),
		BrokerDialer: recordingDialer(brokerRec),
		Config: &config.Config{
			ExitConstraint: brokerproto.AutoConstraint(),
			Broker:         &config.BrokerSource{Kind: "direct", Direct: "https://broker.example"},
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Close()

	got := waitForDial(brokerRec, 10*time.Second)
	if len(got) == 0 {
		t.Fatal("the broker fetch never rode BrokerDialer")
	}
	for _, d := range got {
		if d != "tcp broker.example:443" {
			t.Fatalf("unexpected fetch dial %q, want the broker address only", d)
		}
	}
	if got := stackRec.recorded(); len(got) != 0 {
		t.Fatalf("StackDialer carried broker fetches: %v", got)
	}
}

// TestBrokerDialerDefaultsToStack verifies the single-dialer fallback: an
// embedder that sets only StackDialer (the historical shape) still has its
// broker fetches carried by it.
func TestBrokerDialerDefaultsToStack(t *testing.T) {
	stackRec := &dialRecorder{}
	c, err := Start(context.Background(), Options{
		NoListener:  true,
		StackDialer: recordingDialer(stackRec),
		Config: &config.Config{
			ExitConstraint: brokerproto.AutoConstraint(),
			Broker:         &config.BrokerSource{Kind: "direct", Direct: "https://broker.example"},
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Close()

	got := waitForDial(stackRec, 10*time.Second)
	if len(got) == 0 {
		t.Fatal("the broker fetch never fell back to StackDialer")
	}
	if got[0] != "tcp broker.example:443" {
		t.Fatalf("first fallback dial = %q, want the broker address", got[0])
	}
}
