package geph

import (
	"context"
	"fmt"
	"net"

	pub "github.com/goose-network/goose-plugin-api"
)

func init() {
	pub.Register("geph", New)
}

// outbound is the "geph" protocol outbound: a dial into the live geph
// provider registered under the id in "tunnel". All state lives in the
// provider (the embedded geph5 client and its session manager), so the
// outbound itself carries only ids; exitHostname, when non-empty, pins the
// dial to one broker-known exit (the per-server form of the geph outbound —
// see Provider.Outbounds). address is that exit's c2e host:port, reported by
// Address so a chain's previous hop tunnels toward the exit's listener.
type outbound struct {
	id           string
	tunnel       string
	exitHostname string
	address      string
}

// New is the outbound factory registered as protocol "geph". It expects the
// config map the provider's Outbounds emits: {"id": ..., "tunnel": ...} for
// the general outbound, plus {"exit_hostname": ..., "address": ...} on per-exit
// outbounds. Engine-injected keys under the reserved "_dialer"/"_upstream_dialer"
// names are intentionally ignored — this protocol dials in process through its
// provider, never through the stack as an upstream transport.
func New(cfg map[string]any) (pub.Outbound, error) {
	id, _ := cfg["id"].(string)
	tunnel, _ := cfg["tunnel"].(string)
	if id == "" {
		id = "geph"
	}
	if tunnel == "" {
		tunnel = id
	}
	exitHostname, _ := cfg["exit_hostname"].(string)
	address, _ := cfg["address"].(string)
	return &outbound{id: id, tunnel: tunnel, exitHostname: exitHostname, address: address}, nil
}

// DialContext opens a connection to address through the live geph provider's
// session manager, in process — no loopback hop. Only TCP is supported:
// geph5 tunnels carry TCP streams.
func (o *outbound) DialContext(ctx context.Context, network pub.Network, address string) (net.Conn, error) {
	if network != pub.NetworkTCP {
		return nil, fmt.Errorf("geph outbound %s: unsupported network %q (only %q is supported)", o.id, network, pub.NetworkTCP)
	}
	p, ok := lookupLiveProvider(o.tunnel)
	if !ok {
		return nil, fmt.Errorf("geph outbound %s: no live provider for tunnel %q", o.id, o.tunnel)
	}
	if o.exitHostname != "" {
		return p.dialExit(ctx, o.exitHostname, address)
	}
	return p.dialConn(ctx, address)
}

// DialThrough is the goose router's ChainDialer capability: the previous hop
// has already tunneled to this exit's c2e listener (via), so geph establishes a
// one-off authenticated session over that tunnel and opens a stream to target,
// instead of dialing the exit from the local network. Only a pinned per-exit
// outbound can chain — the general "geph" outbound rides an auto (race) route
// that cannot ride a single upstream conn. On success the returned conn owns
// via; on error the router closes it.
func (o *outbound) DialThrough(ctx context.Context, network pub.Network, target string, via net.Conn) (net.Conn, error) {
	if network != pub.NetworkTCP {
		return nil, fmt.Errorf("geph outbound %s: unsupported network %q (only %q is supported)", o.id, network, pub.NetworkTCP)
	}
	if o.exitHostname == "" {
		return nil, fmt.Errorf("geph outbound %s: chaining requires a pinned per-exit outbound (the general auto exit cannot ride a single upstream tunnel)", o.id)
	}
	p, ok := lookupLiveProvider(o.tunnel)
	if !ok {
		return nil, fmt.Errorf("geph outbound %s: no live provider for tunnel %q", o.id, o.tunnel)
	}
	return p.dialExitThrough(ctx, o.exitHostname, target, via)
}

// ID returns the outbound id.
func (o *outbound) ID() string { return o.id }

// Protocol returns "geph".
func (o *outbound) Protocol() string { return "geph" }

// Address reports the proxy-server address a chain's previous hop tunnels
// toward. A pinned per-exit outbound reports the exit's c2e host:port (so an
// upstream hop CONNECTs to the exit's listener, then DialThrough runs the geph
// handshake over that tunnel). The general (aggregate) outbound has no socket
// address — its dials ride a live in-process session pool — so it reports "",
// exactly like the tor aggregate.
//
// The empty address is load-bearing: it keeps the aggregate out of the engine's
// dial-reachability sweep (dialProbeRound skips Address()==""). A pseudo-URI
// such as "geph://<tunnel>" is not a dialable host:port, so net.Dial would fail
// deterministically every round and latch a permanent "unreachable" verdict.
// With per-exit outbounds pin-only, the aggregate is geph's sole auto-selectable
// route, so that verdict would drop it from every first hop (pool, fallback,
// outbound_id pin) with no recovery. Reporting "" means no verdict is ever
// measured, reachableCandidates fails open, and the aggregate stays selectable;
// dispatch dials it via DialContext(target), never via Address.
func (o *outbound) Address() string {
	return o.address
}

// Location returns nil: geph5 exits are identified by pubkey, not by a
// location the client can see (the broker's ExitDescriptor is not surfaced
// per-dial).
func (o *outbound) Location() *pub.Location { return nil }

// Stats returns a zero value; the session manager's own instrumentation
// covers tunnel health.
func (o *outbound) Stats() pub.OutboundStats { return pub.OutboundStats{} }
