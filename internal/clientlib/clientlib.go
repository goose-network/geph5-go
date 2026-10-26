// Package clientlib wires the geph5 client core — auth loop, session manager,
// SOCKS5 listener — into one startable bundle for embedders, as a Go analog of
// the wiring in binaries/geph5-client/src/bin/geph5-client.rs (and
// cmd/geph-client/main.go) minus the command-specific services (vpn, pac,
// port_forward, control RPC).
//
// The goose provider plugin (plugins/geph) embeds the client through this
// library. It lives outside internal/ so the plugin package — which registers
// itself with the goose plugin contract — can sit beside it in the module
// without violating Go's internal-package rule on the goose side.
//
// The Start semantics mirror the psiphon/tor provider plugins: the listener
// binds synchronously (Start returns an error if it cannot), while session
// establishment (broker fetch, exit handshake) proceeds in the background; a
// connection arriving before any session is up simply fails.
//
// Embedders that keep the client inside their own process boundary (the goose
// plugin) set NoListener and dial in process via Client.OpenConn, and pass
// StackDialer so the client's own TCP — broker RPCs and the route tree to the
// exit — goes through the embedder's network stack rather than the raw system
// dialer.
package clientlib

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/geph-official/geph5-go/internal/auth"
	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/config"
	"github.com/geph-official/geph5-go/internal/database"
	"github.com/geph-official/geph5-go/internal/frontedhttp"
	"github.com/geph-official/geph5-go/internal/nanorpc"
	"github.com/geph-official/geph5-go/internal/proxy/socks5"
	"github.com/geph-official/geph5-go/internal/session"
)

// Options configures a client bundle.
type Options struct {
	// Socks5Listen is the address the embedded SOCKS5 listener binds. Empty
	// means "127.0.0.1:0" (an ephemeral loopback port); the actual bound
	// address is reported by Client.SocksAddr. Ignored when NoListener is
	// set.
	Socks5Listen string

	// NoListener skips the embedded SOCKS5 listener entirely: Start binds no
	// port, and embedders dial in process through Client.OpenConn. This is how
	// the goose plugin consumes the client — no loopback hop between the
	// engine and the embedded client.
	NoListener bool

	// StackDialer, when non-nil, establishes every raw TCP connection the
	// client itself makes (to the broker, and through the route tree to the
	// exit) instead of the system dialer — the embedding process's network
	// stack. Nil is the system dialer, exactly as before.
	StackDialer func(ctx context.Context, network, address string) (net.Conn, error)

	// Config is the client configuration (exit constraint, credentials,
	// broker, ...). Required: a config with no exit constraint cannot start.
	Config *config.Config
}

// Client is a running geph5 client bundle: database, broker client, auth
// manager, session manager, and (unless NoListener) the SOCKS5 listener they
// feed. Use Close to stop everything.
type Client struct {
	cancel  context.CancelFunc
	stopped chan struct{} // closed when all goroutines have exited

	sessMgr   *session.Manager
	openConn  func(ctx context.Context, remote string) (net.Conn, error)
	socksAddr string // the address the SOCKS5 listener actually bound ("" with NoListener)
	broker    *brokerproto.BrokerClient // nil when no broker source is configured
}

// Start loads nothing and guesses nothing: cfg must already carry the exit
// constraint (and credentials/broker as applicable). It initializes the
// database, builds the broker client, starts the auth and session-manager
// goroutines, and binds the SOCKS5 listener.
//
// The SOCKS5 listener binds synchronously (bind errors fail Start), but the
// first session may still be establishing when Start returns; dial through
// SocksAddr only succeeds once at least one session is live.
func Start(ctx context.Context, opts Options) (*Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg := opts.Config
	if cfg == nil {
		return nil, fmt.Errorf("clientlib: Config is required")
	}
	if cfg.ExitConstraint.Kind == "" {
		return nil, fmt.Errorf("clientlib: exit_constraint is required (e.g. \"auto\" or {\"direct\": \"host:port/pubkeyhex\"})")
	}

	// Database at cfg.Cache (in-memory if unset).
	var dbPath string
	if cfg.Cache != nil {
		dbPath = *cfg.Cache
	}
	db, err := database.New(dbPath)
	if err != nil {
		return nil, fmt.Errorf("clientlib: init database at %q: %w", dbPath, err)
	}

	// Broker client. A missing/unbuildable broker is non-fatal — it only
	// disables broker-dependent features (auth fetch, route-broker cache,
	// non-direct exit constraints), exactly like cmd/geph-client/main.go.
	broker, err := BuildBrokerClient(cfg, opts.StackDialer)
	if err != nil {
		log.Printf("clientlib: could not build broker client: %v (broker-dependent features disabled)", err)
		broker = nil
	}

	authMgr := auth.NewManager(cfg, db, broker)
	sessMgr := session.NewManager(cfg, authMgr, broker, db, opts.StackDialer)

	ctx, cancel := context.WithCancel(ctx)
	c := &Client{
		cancel:  cancel,
		stopped: make(chan struct{}),
		sessMgr: sessMgr,
		broker:  broker,
	}

	openConn := sessMgr.AsOpenConnFunc()
	c.openConn = openConn

	// With NoListener, nothing binds: the embedder dials in process through
	// Client.OpenConn. Otherwise bind the SOCKS5 listener up front so Start
	// fails fast on bind errors, and so we can hand back the real bound
	// address for "127.0.0.1:0".
	var ln net.Listener
	if !opts.NoListener {
		listen := opts.Socks5Listen
		if listen == "" {
			listen = "127.0.0.1:0"
		}
		ln, err = net.Listen("tcp", listen)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("clientlib: socks5 listen %s: %w", listen, err)
		}
		c.socksAddr = ln.Addr().String()
	}

	go func() {
		defer close(c.stopped)
		var serveWG sync.WaitGroup

		// SOCKS5 accept loop (owns ln; stops when ctx is canceled). Skipped
		// entirely with NoListener.
		if ln != nil {
			serveWG.Add(1)
			go func() {
				defer serveWG.Done()
				if err := socks5.ServeOn(ctx, ln, openConn); err != nil && ctx.Err() == nil {
					log.Printf("clientlib: socks5 serve stopped: %v", err)
				}
			}()
		}

		// Auth loop (waits on broker; degrades when nil).
		serveWG.Add(1)
		go func() {
			defer serveWG.Done()
			if err := authMgr.AuthLoop(ctx); err != nil && ctx.Err() == nil {
				log.Printf("clientlib: auth loop stopped: %v", err)
			}
		}()

		// Session manager (establishes and maintains the 6 tunnels).
		serveWG.Add(1)
		go func() {
			defer serveWG.Done()
			if err := sessMgr.Run(ctx); err != nil && ctx.Err() == nil {
				log.Printf("clientlib: session manager stopped: %v", err)
			}
		}()

		<-ctx.Done()
		// The context cancel above only delivers the shutdown signal; give the
		// serve loops a moment to observe it and close their listeners before
		// Close returns, so ports are actually free afterwards.
		serveWG.Wait()
	}()

	return c, nil
}

// SocksAddr returns the address the embedded SOCKS5 listener bound (as passed
// in Options, or the ephemeral port actually picked for "127.0.0.1:0"). It is
// empty when the client was started with NoListener, since nothing binds.
func (c *Client) SocksAddr() string { return c.socksAddr }

// OpenConn dials remote through the live session manager, in process: it is
// the same function the SOCKS5 listener hands CONNECTs to, exposed directly so
// embedders (the goose plugin) skip the loopback hop. It fails until at least
// one session is live, just like a CONNECT would.
func (c *Client) OpenConn(ctx context.Context, remote string) (net.Conn, error) {
	if c.openConn == nil {
		return nil, fmt.Errorf("clientlib: no open-conn path")
	}
	return c.openConn(ctx, remote)
}

// SessionCount returns the current number of live exit sessions the session
// manager maintains. It is the readiness signal embedders poll: the SOCKS5
// listener is bound from Start on, but CONNECTs succeed only once this is > 0.
func (c *Client) SessionCount() int { return len(c.sessMgr.LiveSessionInfos()) }

// BrokerClient returns the broker client this client was started with, so
// embedders can make their own broker RPCs (e.g. the exit roster via
// get_net_status) instead of re-building a transport. It errors when no
// broker is configured (standalone/direct setups).
func (c *Client) BrokerClient() (*brokerproto.BrokerClient, error) {
	if c.broker == nil {
		return nil, fmt.Errorf("clientlib: no broker configured")
	}
	return c.broker, nil
}

// Close cancels the client's context and waits for the SOCKS5 listener, auth
// loop, and session manager goroutines to exit.
func (c *Client) Close() {
	c.cancel()
	<-c.stopped
}

// BuildBrokerClient constructs a brokerproto.BrokerClient from the configured
// BrokerSource. Only the "direct" and "fronted" variants are wired here; other
// variants (direct_tcp, aws_lambda, race, priority_race) return an error,
// mirroring cmd/geph-client's buildBrokerClient helper. stackDialer, when
// non-nil, establishes the raw TCP connection to the broker (or its front);
// nil is the system dialer.
func BuildBrokerClient(cfg *config.Config, stackDialer func(ctx context.Context, network, address string) (net.Conn, error)) (*brokerproto.BrokerClient, error) {
	if cfg == nil || cfg.Broker == nil {
		return nil, fmt.Errorf("no broker source configured")
	}
	transport, err := brokerTransportFromSource(cfg.Broker, stackDialer)
	if err != nil {
		return nil, err
	}
	return brokerproto.NewBrokerClient(transport), nil
}

// brokerTransportFromSource builds a nanorpc.RpcTransport for a BrokerSource.
// Only the "direct" and "fronted" variants are wired (mirroring
// cmd/geph-client/main.go); the rest are not yet implemented.
func brokerTransportFromSource(src *config.BrokerSource, stackDialer func(ctx context.Context, network, address string) (net.Conn, error)) (nanorpc.RpcTransport, error) {
	switch src.Kind {
	case "direct":
		// Direct broker URL, no domain fronting.
		t, err := frontedhttp.New(src.Direct, "", nil, stackDialer)
		if err != nil {
			return nil, err
		}
		return t, nil
	case "fronted":
		if src.Fronted == nil {
			return nil, fmt.Errorf("fronted broker source missing payload")
		}
		t, err := frontedhttp.New(src.Fronted.Front, src.Fronted.Host, src.Fronted.OverrideDNS, stackDialer)
		if err != nil {
			return nil, err
		}
		return t, nil
	case "direct_tcp", "aws_lambda", "race", "priority_race":
		return nil, fmt.Errorf("broker source kind %q not yet implemented", src.Kind)
	default:
		return nil, fmt.Errorf("unknown broker source kind %q", src.Kind)
	}
}
