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
// see Provider.Outbounds).
type outbound struct {
	id           string
	tunnel       string
	exitHostname string
}

// New is the outbound factory registered as protocol "geph". It expects the
// config map the provider's Outbounds emits: {"id": ..., "tunnel": ...} for
// the general outbound, plus {"exit_hostname": ...} on per-exit outbounds.
// Engine-injected keys under the reserved "_dialer"/"_upstream_dialer" names
// are intentionally ignored — this protocol dials in process through its
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
	return &outbound{id: id, tunnel: tunnel, exitHostname: exitHostname}, nil
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

// ID returns the outbound id.
func (o *outbound) ID() string { return o.id }

// Protocol returns "geph".
func (o *outbound) Protocol() string { return "geph" }

// Address reports the tunnel id the outbound resolves at dial time; there is
// no socket address, since dials never leave the process.
func (o *outbound) Address() string { return "geph://" + o.tunnel }

// Location returns nil: geph5 exits are identified by pubkey, not by a
// location the client can see (the broker's ExitDescriptor is not surfaced
// per-dial).
func (o *outbound) Location() *pub.Location { return nil }

// Stats returns a zero value; the session manager's own instrumentation
// covers tunnel health.
func (o *outbound) Stats() pub.OutboundStats { return pub.OutboundStats{} }
