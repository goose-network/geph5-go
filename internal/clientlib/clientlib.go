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
	// address is reported by Client.SocksAddr.
	Socks5Listen string

	// Config is the client configuration (exit constraint, credentials,
	// broker, ...). Required: a config with no exit constraint cannot start.
	Config *config.Config
}

// Client is a running geph5 client bundle: database, broker client, auth
// manager, session manager, and the SOCKS5 listener they feed. Use Close to
// stop everything.
type Client struct {
	cancel  context.CancelFunc
	stopped chan struct{} // closed when all goroutines have exited

	sessMgr   *session.Manager
	socksAddr string // the address the SOCKS5 listener actually bound
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
	broker, err := BuildBrokerClient(cfg)
	if err != nil {
		log.Printf("clientlib: could not build broker client: %v (broker-dependent features disabled)", err)
		broker = nil
	}

	authMgr := auth.NewManager(cfg, db, broker)
	sessMgr := session.NewManager(cfg, authMgr, broker, db)

	// Bind the SOCKS5 listener up front so Start fails fast on bind errors,
	// and so we can hand back the real bound address for "127.0.0.1:0".
	listen := opts.Socks5Listen
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("clientlib: socks5 listen %s: %w", listen, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	c := &Client{
		cancel:    cancel,
		stopped:   make(chan struct{}),
		sessMgr:   sessMgr,
		socksAddr: ln.Addr().String(),
	}

	openConn := sessMgr.AsOpenConnFunc()

	go func() {
		defer close(c.stopped)
		var serveWG sync.WaitGroup

		// SOCKS5 accept loop (owns ln; stops when ctx is canceled).
		serveWG.Add(1)
		go func() {
			defer serveWG.Done()
			if err := socks5.ServeOn(ctx, ln, openConn); err != nil && ctx.Err() == nil {
				log.Printf("clientlib: socks5 serve stopped: %v", err)
			}
		}()

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
// in Options, or the ephemeral port actually picked for "127.0.0.1:0").
func (c *Client) SocksAddr() string { return c.socksAddr }

// SessionCount returns the current number of live exit sessions the session
// manager maintains. It is the readiness signal embedders poll: the SOCKS5
// listener is bound from Start on, but CONNECTs succeed only once this is > 0.
func (c *Client) SessionCount() int { return len(c.sessMgr.LiveSessionInfos()) }

// Close cancels the client's context and waits for the SOCKS5 listener, auth
// loop, and session manager goroutines to exit.
func (c *Client) Close() {
	c.cancel()
	<-c.stopped
}

// BuildBrokerClient constructs a brokerproto.BrokerClient from the configured
// BrokerSource. Only the "direct" and "fronted" variants are wired here; other
// variants (direct_tcp, aws_lambda, race, priority_race) return an error,
// mirroring cmd/geph-client's buildBrokerClient helper.
func BuildBrokerClient(cfg *config.Config) (*brokerproto.BrokerClient, error) {
	if cfg == nil || cfg.Broker == nil {
		return nil, fmt.Errorf("no broker source configured")
	}
	transport, err := brokerTransportFromSource(cfg.Broker)
	if err != nil {
		return nil, err
	}
	return brokerproto.NewBrokerClient(transport), nil
}

// brokerTransportFromSource builds a nanorpc.RpcTransport for a BrokerSource.
// Only the "direct" and "fronted" variants are wired (mirroring
// cmd/geph-client/main.go); the rest are not yet implemented.
func brokerTransportFromSource(src *config.BrokerSource) (nanorpc.RpcTransport, error) {
	switch src.Kind {
	case "direct":
		// Direct broker URL, no domain fronting.
		t, err := frontedhttp.New(src.Direct, "", nil)
		if err != nil {
			return nil, err
		}
		return t, nil
	case "fronted":
		if src.Fronted == nil {
			return nil, fmt.Errorf("fronted broker source missing payload")
		}
		t, err := frontedhttp.New(src.Fronted.Front, src.Fronted.Host, src.Fronted.OverrideDNS)
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
