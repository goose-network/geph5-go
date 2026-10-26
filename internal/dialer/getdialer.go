package dialer

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/geph-official/geph5-go/internal/blake3"
	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/conntest"
	"github.com/geph-official/geph5-go/internal/database"
	"github.com/geph-official/geph5-go/internal/hexdialer"
	"github.com/geph-official/geph5-go/internal/meeklike"
	"github.com/geph-official/geph5-go/internal/routecache"
	"github.com/geph-official/geph5-go/internal/sillad"
	"github.com/geph-official/geph5-go/internal/sosistab3"
)

// GetDialer is the route-to-dialer compiler. It mirrors get_dialer() in
// get_dialer.rs: given a client Config, a broker client, and a persistent KV
// store, it returns the exit's ed25519 public key, its ExitDescriptor, and a
// sillad.Dialer that produces a single pre-authentication pipe to the exit.
//
// exitRouteArgs supplies the connect token, signature, and client metadata
// needed for the broker.GetExitRoute RPC (in the Rust client these are obtained
// from get_connect_token / get_device_metadata; here the caller, which owns the
// auth machinery, passes them in).
//
// stackDialer, when non-nil, establishes the raw TCP connections to the exit
// (see BoundTcpDialer.DialContext); nil dials with the system dialer.
//
// Flow:
//  1. If cfg.ExitConstraint is "direct": parse "host:port/pubkeyhex", resolve
//     the host, build a ConnTestDialer{ping_count:1, inner: BoundTcpDialer{addr}}.
//     Return the pubkey, a placeholder ExitDescriptor, and the dialer.
//  2. Otherwise: try ReadCachedExitRoute; if unexpired (exit.expiry > now), use
//     it. Otherwise call broker.GetExitRoute, verify the JsonSigned signature
//     (domain "exit-route", check pubkey hex == cfg.BrokerKeys.Master), cache
//     it, and use it. On fresh-route failure, fall back to the cached route.
//  3. combine_exit_route: if allow_direct, Race[ConnTest{ping_count:1,
//     lower:Tcp(exit.c2e_listen)}, Delay{1000ms, lower:route}]; else just route.
//  4. route_to_dialer: recursively compile the RouteDescriptor tree into a
//     sillad.Dialer.
func GetDialer(
	ctx context.Context,
	cfg brokerproto.ExitConstraint,
	allowDirect bool,
	brokerKeys *BrokerKeys,
	brokerClient *brokerproto.BrokerClient,
	db *database.Database,
	exitRouteArgs brokerproto.GetExitRouteArgs,
	stackDialer func(ctx context.Context, network, address string) (net.Conn, error),
) (exitPubkey []byte, exit brokerproto.ExitDescriptor, dialer sillad.Dialer, err error) {
	// 1. Direct constraint: parse "host:port/pubkeyhex".
	if cfg.Kind == "direct" {
		return getDialerDirect(ctx, cfg.Direct, stackDialer)
	}

	// 2. Try the cached exit route first.
	cached, cacheErr := routecache.ReadCachedExitRoute(ctx, db, cfg)
	if cacheErr == nil && cached != nil && exitRouteIsUnexpired(*cached) {
		return dialerFromExitRoute(*cached, allowDirect, stackDialer)
	}

	// 3. Fetch a fresh exit route from the broker.
	fresh, freshErr := fetchFreshExitRoute(ctx, brokerClient, brokerKeys, db, cfg, exitRouteArgs)
	if freshErr == nil {
		return dialerFromExitRoute(fresh, allowDirect, stackDialer)
	}

	// 4. Fresh route failed: fall back to the cached route (even if expired).
	if cacheErr == nil && cached != nil {
		return dialerFromExitRoute(*cached, allowDirect, stackDialer)
	}
	if cacheErr != nil {
		return nil, brokerproto.ExitDescriptor{}, nil, fmt.Errorf(
			"dialer: fresh exit route unavailable and cached route lookup failed: %w (fresh err: %v)",
			cacheErr, freshErr)
	}
	return nil, brokerproto.ExitDescriptor{}, nil, fmt.Errorf(
		"dialer: fresh exit route unavailable and no cached route found: %w", freshErr)
}

// BrokerKeys is the subset of the client config's broker verification keys
// that the dialer needs. We accept a small dedicated struct so this package
// does not import internal/config (avoiding a cycle risk and keeping the
// compiler focused on routes). Callers that hold a config.BrokerKeys can pass
// &dialer.BrokerKeys{Master: cfg.BrokerKeys.Master}.
type BrokerKeys struct {
	// Master is the hex-encoded ed25519 master public key used to verify
	// signed exit routes. Empty means "trust blindly" (matches the Rust
	// warn-and-trust behavior when broker_keys is None).
	Master string
}

// BrokerKeysFromMasterHex is a convenience constructor wrapping a hex master
// key string.
func BrokerKeysFromMasterHex(masterHex string) *BrokerKeys {
	return &BrokerKeys{Master: masterHex}
}

// getDialerDirect handles the ExitConstraint::Direct case: parse
// "host:port/pubkeyhex", resolve the host, and build a ConnTestDialer wrapping
// a BoundTcpDialer. Returns the pubkey, a placeholder ExitDescriptor, and the
// dialer. stackDialer (when non-nil) becomes the BoundTcpDialer's raw dialer.
func getDialerDirect(ctx context.Context, direct string, stackDialer func(ctx context.Context, network, address string) (net.Conn, error)) ([]byte, brokerproto.ExitDescriptor, sillad.Dialer, error) {
	dir, pubkeyHex, ok := splitOnce(direct, '/')
	if !ok {
		return nil, brokerproto.ExitDescriptor{}, nil, errors.New("dialer: did not find / in a direct constraint")
	}
	pubkey, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return nil, brokerproto.ExitDescriptor{}, nil, fmt.Errorf("dialer: cannot decode pubkey as hex: %w", err)
	}
	if len(pubkey) != 32 {
		return nil, brokerproto.ExitDescriptor{}, nil, fmt.Errorf("dialer: pubkey wrong length: got %d, want 32", len(pubkey))
	}
	resolveCtx, cancel := context.WithTimeout(ctx, dialResolveTimeout)
	defer cancel()
	addr, err := pickRandomAddr(resolveCtx, dir)
	if err != nil {
		return nil, brokerproto.ExitDescriptor{}, nil, fmt.Errorf("dialer: could not resolve destination for direct exit connection: %w", err)
	}
	// direct_route = ConnTest{ ping_count: 1, lower: Tcp(addr) }
	dialer := conntest.Dialer{
		PingCount: 1,
		Inner:     BoundTcpDialer{DestAddr: addr, DialContext: stackDialer},
	}
	placeholder := brokerproto.ExitDescriptor{
		C2EListen: "0.0.0.0:0",
		B2EListen: "0.0.0.0:0",
		Country:   "AW",
		City:      "",
		Load:      0,
		Expiry:    0,
	}
	return pubkey, placeholder, dialer, nil
}

// fetchFreshExitRoute calls broker.GetExitRoute, verifies the JsonSigned
// signature, caches the result, and returns the ExitRouteDescriptor.
func fetchFreshExitRoute(
	ctx context.Context,
	brokerClient *brokerproto.BrokerClient,
	brokerKeys *BrokerKeys,
	db *database.Database,
	cfg brokerproto.ExitConstraint,
	args brokerproto.GetExitRouteArgs,
) (brokerproto.ExitRouteDescriptor, error) {
	if brokerClient == nil {
		return brokerproto.ExitRouteDescriptor{}, errors.New("dialer: broker client is nil")
	}
	signed, err := brokerClient.GetExitRoute(ctx, args)
	if err != nil {
		return brokerproto.ExitRouteDescriptor{}, fmt.Errorf("dialer: broker get_exit_route: %w", err)
	}
	exitRoute, err := verifyExitRoute(signed, brokerKeys)
	if err != nil {
		return brokerproto.ExitRouteDescriptor{}, fmt.Errorf("dialer: could not verify exit route: %w", err)
	}
	// Best-effort cache write; a failure here is not fatal.
	if db != nil {
		if werr := routecache.WriteCachedExitRoute(ctx, db, cfg, exitRoute); werr != nil {
			// Mirror the Rust warn-and-continue behavior.
			_ = werr
		}
	}
	return exitRoute, nil
}

// verifyExitRoute verifies a JsonSigned<ExitRouteDescriptor> under the
// "exit-route" domain, checking that the signer's pubkey matches the configured
// broker master key (hex). Mirrors verify_exit_route in get_dialer.rs.
func verifyExitRoute(signed *brokerproto.JsonSigned, brokerKeys *BrokerKeys) (brokerproto.ExitRouteDescriptor, error) {
	var route brokerproto.ExitRouteDescriptor
	validator := func(pk [32]byte) bool {
		if brokerKeys == nil || brokerKeys.Master == "" {
			// Trust blindly when no broker keys were provided, matching the
			// Rust warn-and-trust behavior.
			return true
		}
		return hex.EncodeToString(pk[:]) == brokerKeys.Master
	}
	if err := signed.Verify(brokerproto.DomainExitRoute, validator, &route); err != nil {
		return brokerproto.ExitRouteDescriptor{}, err
	}
	return route, nil
}

// dialerFromExitRoute builds the combined route tree and compiles it into a
// sillad.Dialer. Mirrors dialer_from_exit_route in get_dialer.rs. stackDialer
// (when non-nil) is threaded into every TCP dialer the tree compiles to.
func dialerFromExitRoute(exitRoute brokerproto.ExitRouteDescriptor, allowDirect bool, stackDialer func(ctx context.Context, network, address string) (net.Conn, error)) ([]byte, brokerproto.ExitDescriptor, sillad.Dialer, error) {
	combined := combineExitRoute(exitRoute.Exit, exitRoute.Route, allowDirect)
	d := routeToDialer(&combined, stackDialer)
	return exitRoute.ExitPubkey, exitRoute.Exit, d, nil
}

// exitRouteIsUnexpired reports whether the route's expiry is strictly greater
// than the current Unix time. Mirrors exit_route_is_unexpired.
func exitRouteIsUnexpired(route brokerproto.ExitRouteDescriptor) bool {
	now := uint64(time.Now().Unix())
	return route.Exit.Expiry > now
}

// combineExitRoute mirrors combine_exit_route: if allowDirect, race a direct
// ConnTest-wrapped TCP dial to the exit's c2e_listen against the broker route
// (delayed by 1s so the direct path wins when it works); otherwise return the
// route unchanged.
func combineExitRoute(exit brokerproto.ExitDescriptor, route brokerproto.RouteDescriptor, allowDirect bool) brokerproto.RouteDescriptor {
	if !allowDirect {
		return route
	}
	c2e := brokerproto.RouteDescriptor{Kind: "tcp", TcpAddr: exit.C2EListen}
	direct := brokerproto.RouteDescriptor{
		Kind:      "conntest",
		PingCount: 1,
		Lower:     &c2e,
	}
	delayed := brokerproto.RouteDescriptor{
		Kind:         "delay",
		Milliseconds: 1000,
		Lower:        &route,
	}
	return brokerproto.RouteDescriptor{
		Kind:   "race",
		Routes: []brokerproto.RouteDescriptor{direct, delayed},
	}
}

// routeToDialer recursively compiles a RouteDescriptor tree into a sillad.Dialer.
// Mirrors route_to_dialer in get_dialer.rs. stackDialer (when non-nil) is
// attached to every TCP dialer the tree compiles to.
func routeToDialer(route *brokerproto.RouteDescriptor, stackDialer func(ctx context.Context, network, address string) (net.Conn, error)) sillad.Dialer {
	switch route.Kind {
	case "tcp":
		return BoundTcpDialer{DestAddr: route.TcpAddr, DialContext: stackDialer}

	case "sosistab3":
		inner := routeToDialer(route.Lower, stackDialer)
		return sosistab3Dialer{inner: inner, cookie: sosistab3.NewCookie(route.Cookie)}

	case "race":
		if len(route.Routes) == 0 {
			return sillad.FailingDialer{Err: errors.New("dialer: empty race route")}
		}
		inner := make([]sillad.Dialer, len(route.Routes))
		for i := range route.Routes {
			inner[i] = routeToDialer(&route.Routes[i], stackDialer)
		}
		return sillad.RaceDialer{Inner: inner}

	case "fallback":
		if len(route.Routes) == 0 {
			return sillad.FailingDialer{Err: errors.New("dialer: empty fallback route")}
		}
		inner := make([]sillad.Dialer, len(route.Routes))
		for i := range route.Routes {
			inner[i] = routeToDialer(&route.Routes[i], stackDialer)
		}
		return sillad.FallbackDialer{Inner: inner}

	case "timeout":
		inner := routeToDialer(route.Lower, stackDialer)
		return sillad.TimeoutDialer{Inner: inner, Timeout: time.Duration(route.Milliseconds) * time.Millisecond}

	case "delay":
		inner := routeToDialer(route.Lower, stackDialer)
		return sillad.DelayDialer{Inner: inner, Delay: time.Duration(route.Milliseconds) * time.Millisecond}

	case "conntest":
		inner := routeToDialer(route.Lower, stackDialer)
		return conntest.Dialer{Inner: inner, PingCount: int(route.PingCount)}

	case "hex":
		inner := routeToDialer(route.Lower, stackDialer)
		return hexdialer.Dialer{Inner: inner}

	case "plain_tls":
		inner := routeToDialer(route.Lower, stackDialer)
		sni := "example.com"
		if route.SNIDomain != nil && *route.SNIDomain != "" {
			sni = *route.SNIDomain
		}
		return plainTLSDialer{inner: inner, sni: sni}

	case "meeklike":
		inner := routeToDialer(route.Lower, stackDialer)
		key := blake3.Hash([]byte(route.MeeklikeKey))
		cfg := meeklike.Config{
			MaxInflight: route.MeeklikeCfg.MaxInflight,
			Mss:         route.MeeklikeCfg.Mss,
			Base64:      route.MeeklikeCfg.Base64,
		}
		return meeklike.MeeklikeDialer{Inner: inner, Key: key, Cfg: cfg}

	case "other", "":
		return sillad.FailingDialer{Err: fmt.Errorf("dialer: unsupported route kind %q", route.Kind)}

	default:
		return sillad.FailingDialer{Err: fmt.Errorf("dialer: unknown route kind %q", route.Kind)}
	}
}

// sosistab3Dialer adapts the sosistab3 client handshake to sillad.Dialer. It
// dials the inner transport, then runs the sosistab3 client handshake over the
// resulting pipe (which is a net.Conn) and returns the established sosistab3
// Pipe.
type sosistab3Dialer struct {
	inner  sillad.Dialer
	cookie sosistab3.Cookie
}

func (d sosistab3Dialer) Dial(ctx context.Context) (sillad.Pipe, error) {
	lower, err := d.inner.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("dialer: sosistab3 inner dial: %w", err)
	}
	conn, ok := lower.(net.Conn)
	if !ok {
		// sillad.Pipe embeds net.Conn, so every Pipe is a net.Conn. This is a
		// defensive fallback that should not trigger in practice.
		lower.Close()
		return nil, errors.New("dialer: sosistab3 inner pipe is not a net.Conn")
	}
	pipe, err := sosistab3.Dial(conn, d.cookie)
	if err != nil {
		lower.Close()
		return nil, fmt.Errorf("dialer: sosistab3 handshake: %w", err)
	}
	return pipe, nil
}

// plainTLSDialer wraps an inner dialer with a TLS client that accepts any
// certificate (InsecureSkipVerify) and caps the protocol at TLS 1.2, matching
// the Rust PlainTls route (native_tls with danger_accept_invalid_certs and
// max_protocol_version Tlsv12). The SNI is taken from sni_domain, defaulting to
// "example.com".
type plainTLSDialer struct {
	inner sillad.Dialer
	sni   string
}

func (d plainTLSDialer) Dial(ctx context.Context) (sillad.Pipe, error) {
	lower, err := d.inner.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("dialer: tls inner dial: %w", err)
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
		ServerName:         d.sni,
	}
	// Wrap the raw conn in TLS. We use the lower pipe's underlying net.Conn.
	raw, ok := lower.(net.Conn)
	if !ok {
		lower.Close()
		return nil, errors.New("dialer: tls inner pipe is not a net.Conn")
	}
	tlsConn := tls.Client(raw, tlsConfig)
	// HandshakeContext respects the context deadline/cancellation.
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		lower.Close()
		return nil, fmt.Errorf("dialer: tls handshake: %w", err)
	}
	return &sillad.ConnPipe{
		Conn:        tlsConn,
		ProtocolStr: "tls",
		RemoteStr:   lower.RemoteAddrStr(),
	}, nil
}

// splitOnce splits s on the first occurrence of sep, returning the part before
// sep, the part after sep, and ok=true. If sep is not present, ok=false.
// Mirrors Rust's str::split_once.
func splitOnce(s string, sep byte) (before, after string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// Ensure the dialers satisfy the sillad.Dialer interface.
var (
	_ sillad.Dialer = BoundTcpDialer{}
	_ sillad.Dialer = sosistab3Dialer{}
	_ sillad.Dialer = plainTLSDialer{}
)
