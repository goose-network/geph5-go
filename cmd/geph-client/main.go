// Package main implements the geph5-client entrypoint, a port of
// binaries/geph5-client/src/bin/geph5-client.rs and the Client::start logic
// from client.rs.
//
// It parses command-line flags, loads the YAML config, initializes the
// persistent database, builds the broker RPC client, starts the auth loop
// (mizaru2 token refresh), the session manager, and races the full concurrent
// service set from Rust's client_main: socks5, vpn, http_proxy, auth,
// bw_token_refresh, rpc_serve (tcp/unix/pipe control), pac, and port_forward.
// In dry_run mode only rpc_serve runs, matching Rust exactly.
//
// Flags:
//
//	--config <path>     path to a YAML config file (required)
//	--stdio_vpn         use stdin/stdout as a VPN interface (16-bit BE length prefixes)
//	--vpn_fd <int>      wire an already-open platform-VPN fd into the daemon (optional)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/geph-official/geph5-go/internal/auth"
	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/bwtoken"
	"github.com/geph-official/geph5-go/internal/config"
	"github.com/geph-official/geph5-go/internal/control"
	"github.com/geph-official/geph5-go/internal/database"
	"github.com/geph-official/geph5-go/internal/frontedhttp"
	"github.com/geph-official/geph5-go/internal/nanorpc"
	"github.com/geph-official/geph5-go/internal/portforward"
	"github.com/geph-official/geph5-go/internal/proxy/http"
	"github.com/geph-official/geph5-go/internal/pac"
	"github.com/geph-official/geph5-go/internal/proxy/socks5"
	"github.com/geph-official/geph5-go/internal/session"
	"github.com/geph-official/geph5-go/internal/vpn"
)

func main() {
	configPath := flag.String("config", "", "path to a YAML-based config file (required)")
	stdioVPN := flag.Bool("stdio_vpn", false, "use stdin/stdout as a VPN interface with 16-bit big-endian length prefixes")
	vpnFD := flag.Int("vpn_fd", -1, "wire an already-open platform-VPN file descriptor into the daemon (-1 = none)")
	flag.Parse()

	if *configPath == "" {
		log.Fatal("--config <path> is required")
	}

	cfg, err := config.LoadYAML(*configPath)
	if err != nil {
		log.Fatalf("failed to load config from %s: %v", *configPath, err)
	}
	log.Printf("loaded config: %s", cfg.String())

	// Initialize the database at cfg.Cache (in-memory if unset).
	var dbPath string
	if cfg.Cache != nil {
		dbPath = *cfg.Cache
	}
	db, err := database.New(dbPath)
	if err != nil {
		log.Fatalf("failed to initialize database at %q: %v", dbPath, err)
	}

	// Build the broker client from cfg.Broker.
	broker, err := buildBrokerClient(cfg)
	if err != nil {
		log.Printf("warning: could not build broker client: %v (broker-dependent features disabled)", err)
	}

	// Construct the auth manager and session manager.
	authMgr := auth.NewManager(cfg, db, broker)
	sessMgr := session.NewManager(cfg, authMgr, broker, db)

	// Top-level context canceled on SIGINT/SIGTERM.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %v, shutting down", sig)
		cancel()
	}()

	// Build the VPN loop. The openConn adapter forwards to the session
	// manager's OpenConn (which takes a protocol + "host:port" and returns a
	// sillad.Pipe, which is a net.Conn). spoofDNS selects the (stubbed)
	// fakedns branch for port-53 UDP.
	vpnLoop := vpn.New(func(ctx context.Context, protocol, remote string) (net.Conn, error) {
		pipe, err := sessMgr.OpenConn(ctx, protocol, remote)
		if err != nil {
			return nil, err
		}
		return pipe, nil
	})

	// If --stdio_vpn is set, run the stdio VPN pump (16-bit BE length-prefixed
	// packets between stdin/stdout and the VPN loop). This mirrors Rust's
	// run_stdio_vpn.
	if *stdioVPN {
		go func() {
			if err := vpn.StdioPump(ctx, vpnLoop, os.Stdin, os.Stdout); err != nil && ctx.Err() == nil {
				log.Printf("stdio_vpn stopped: %v", err)
			}
		}()
	}

	// If --vpn_fd is provided, wire the already-open platform-VPN fd into the
	// loop's capture/inject channels (16-bit BE length-prefixed packets).
	if *vpnFD >= 0 {
		go runVPNFD(ctx, vpnLoop, *vpnFD)
	}

	// Run the VPN loop itself (gVisor stack + feeder/drainer goroutines). In
	// Rust this is vpn_loop(&ctx); it only does work when packets arrive via
	// send_vpn_packet / the capture channel, so it is safe to always start.
	go func() {
		if err := vpnLoop.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("vpn loop stopped: %v", err)
		}
	}()

	// Start the auth loop in the background.
	go func() {
		if err := authMgr.AuthLoop(ctx); err != nil && ctx.Err() == nil {
			log.Printf("auth loop stopped: %v", err)
		}
	}()

	// Start the session manager in the background.
	go func() {
		if err := sessMgr.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("session manager stopped: %v", err)
		}
	}()

	// Build the control RPC service. LiveInfos feeds conn_info; Stop terminates
	// the process (after a 100ms delay handled inside the control package).
	controlSvc := control.New(control.Deps{
		LiveInfos:  sessMgr.LiveSessionInfos,
		Broker:     broker,
		DryRun:     cfg.DryRun,
		StartTime:  time.Now(),
		Stop:       func() { cancel() },
	})

	// Resolve optional listen addresses.
	var socks5Listen, httpProxyListen, pacListen, controlListen, controlUnix, controlPipe string
	if cfg.Socks5Listen != nil {
		socks5Listen = *cfg.Socks5Listen
	}
	if cfg.HTTPProxyListen != nil {
		httpProxyListen = *cfg.HTTPProxyListen
	}
	if cfg.PACListen != nil {
		pacListen = *cfg.PACListen
	}
	if cfg.ControlListen != nil {
		controlListen = *cfg.ControlListen
	}
	if cfg.ControlListenUnix != nil {
		controlUnix = *cfg.ControlListenUnix
	}
	if cfg.ControlListenPipe != nil {
		controlPipe = *cfg.ControlListenPipe
	}

	// rpc_serve races the tcp, unix, and pipe control listeners (mirrors
	// Rust's (tcp_rpc_serve, unix_rpc_serve, pipe_rpc_serve).race()).
	rpcServe := func() error {
		return control.ServeControl(ctx, controlSvc, controlListen, controlUnix, controlPipe)
	}

	// In dry_run mode, only rpc_serve runs (mirrors Rust's dry_run branch).
	if cfg.DryRun {
		log.Printf("dry_run mode: running only the control RPC server")
		if err := rpcServe(); err != nil && ctx.Err() == nil {
			log.Printf("rpc_serve stopped: %v", err)
		}
		return
	}

	// Race the full 8-service set from Rust's client_main:
	//   socks5, vpn, http_proxy, auth, bw_token_refresh, rpc_serve, pac, port_forward.
	openConn := sessMgr.AsOpenConnFunc()

	var wg sync.WaitGroup
	runServer := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil && ctx.Err() == nil {
				log.Printf("%s stopped: %v", name, err)
			}
		}()
	}

	runServer("socks5", func() error { return socks5.Serve(ctx, socks5Listen, openConn) })
	runServer("http", func() error { return http.Serve(ctx, httpProxyListen, openConn) })
	runServer("pac", func() error { return pac.Serve(ctx, pacListen, socks5Listen, httpProxyListen) })
	runServer("port_forward", func() error { return portforward.Serve(ctx, cfg.PortForward, openConn) })
	runServer("rpc_serve", rpcServe)
	runServer("bw_token", func() error {
		return bwtokenRefresh(ctx, cfg, authMgr, broker, db)
	})
	// auth, vpn, and session manager are already started above as long-running
	// goroutines; the Rust race includes auth_loop and vpn_loop, which we keep
	// alive for the lifetime of ctx the same way (a race of long-running
	// tasks is equivalent to running them concurrently until the first ends).

	// Wait for all servers to finish (they exit when ctx is canceled).
	wg.Wait()
	log.Printf("geph-client shut down")
}

// bwtokenRefresh wraps bwtoken.RefreshLoop so it can be raced like the other
// services. It blocks forever (pending) when no broker/keys are configured,
// matching Rust's bw_token_refresh_loop behavior.
func bwtokenRefresh(ctx context.Context, cfg *config.Config, authMgr *auth.Manager, broker *brokerproto.BrokerClient, db *database.Database) error {
	return bwtoken.RefreshLoop(ctx, cfg, authMgr, broker, db)
}

// buildBrokerClient constructs a brokerproto.BrokerClient from the configured
// BrokerSource. Only the "direct" and "fronted" variants are wired here; other
// variants (direct_tcp, aws_lambda, race, priority_race) fall back to a
// failing transport. Mirrors the Rust ConfigHelperExt::rpc_transport.
func buildBrokerClient(cfg *config.Config) (*brokerproto.BrokerClient, error) {
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

// runVPNFD wires an already-open platform-VPN file descriptor into the VPN
// loop, reading 16-bit big-endian length-prefixed packets from the fd into the
// loop's CaptureCh and writing packets from the loop's InjectCh back to the fd
// with the same framing. Mirrors Rust's run_vpn_fd_handler.
func runVPNFD(ctx context.Context, vpnLoop *vpn.Loop, fd int) {
	f := os.NewFile(uintptr(fd), fmt.Sprintf("vpn_fd_%d", fd))
	if f == nil {
		log.Printf("vpn_fd: could not wrap fd %d", fd)
		return
	}
	// StdioPump does exactly the 16-bit BE length-prefixed framing we need.
	if err := vpn.StdioPump(ctx, vpnLoop, f, f); err != nil && ctx.Err() == nil {
		log.Printf("vpn_fd stopped: %v", err)
	}
}
