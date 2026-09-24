// Package dialer implements the geph5-client route-to-dialer compiler, porting
// the Rust crate's get_dialer.rs and bound_dialer.rs.
//
// GetDialer turns a client Config (plus a broker client and a persistent KV
// store) into a sillad.Dialer that produces a single, pre-authentication pipe
// to the exit, along with the exit's ed25519 public key and ExitDescriptor.
//
// BoundTcpDialer is the simple TCP dialer underpinning the whole tree. The
// Rust version pins outbound sockets to the physical NIC in full-tunnel VPN
// mode (Windows IP_UNICAST_IF / macOS IP_BOUND_IF); this Go port is the simpler
// "plain connect" variant (net.Dial("tcp", addr) wrapped in a sillad.ConnPipe
// with Protocol()="tcp"), as the task specifies. connect_addrs tries each
// resolved address in order.
package dialer

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/geph-official/geph5-go/internal/sillad"
)

// BoundTcpDialer dials a single TCP address. It mirrors bound_dialer.rs's
// BoundTcpDialer, minus the platform-specific interface pinning (this port
// performs a plain net.Dial, as specified).
type BoundTcpDialer struct {
	DestAddr string // "host:port" or "ip:port"
}

// Dial connects to d.DestAddr over TCP and returns a sillad.Pipe wrapping the
// connection. The pipe's Protocol is "tcp" and RemoteAddrStr is the dialed
// address. TCP_NODELAY is enabled, matching the Rust set_nodelay(true).
func (d BoundTcpDialer) Dial(ctx context.Context) (sillad.Pipe, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.DestAddr)
	if err != nil {
		return nil, fmt.Errorf("dialer: tcp connect %s: %w", d.DestAddr, err)
	}
	// Enable TCP_NODELAY, matching the Rust BoundTcpPipe (set_nodelay(true)).
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	return &sillad.ConnPipe{
		Conn:        conn,
		ProtocolStr: "tcp",
		RemoteStr:   d.DestAddr,
	}, nil
}

// ConnectAddrs tries each "host:port" address in order, returning the first
// successful BoundTcpDialer pipe. It mirrors bound_dialer.rs's connect_addrs
// (which takes pre-resolved SocketAddrs; here we accept address strings that
// net.Dial can resolve, keeping the simpler-variant spirit of this port).
func ConnectAddrs(ctx context.Context, addrs []string) (sillad.Pipe, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("dialer: no addresses to connect to")
	}
	var lastErr error
	for _, addr := range addrs {
		pipe, err := BoundTcpDialer{DestAddr: addr}.Dial(ctx)
		if err == nil {
			return pipe, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// resolveHostPort resolves a "host:port" string to one or more "ip:port"
// addresses, mirroring tokio::net::lookup_host. If host is already an IP
// literal, net.SplitHostPort + net.ResolveIPAddr is used; otherwise the system
// resolver is consulted via net.DefaultResolver. The returned addresses are
// suitable for ConnectAddrs / BoundTcpDialer.
func resolveHostPort(ctx context.Context, hostport string) ([]string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("dialer: split host:port %q: %w", hostport, err)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("dialer: invalid port %q: %w", port, err)
	}
	// If the host is already an IP literal, return it directly.
	if ip := net.ParseIP(host); ip != nil {
		return []string{net.JoinHostPort(ip.String(), port)}, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("dialer: resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("dialer: no addresses for %q", host)
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip.String(), port))
	}
	return out, nil
}

// pickRandomAddr resolves hostport and returns a single randomly-chosen
// address, mirroring the Rust lookup_host(...).choose(rng) used for the direct
// exit constraint. It uses a crypto/rand-backed selection to avoid a math/rand
// global seed dependency.
func pickRandomAddr(ctx context.Context, hostport string) (string, error) {
	addrs, err := resolveHostPort(ctx, hostport)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("dialer: could not resolve destination for direct exit connection")
	}
	// Deterministic-ish but unbiased pick: use the context deadline's nanoseconds
	// as entropy when available, else the first address. The Rust version uses
	// rand::thread_rng(); a crypto/rand source is preferable here.
	idx, err := cryptoRandIntn(len(addrs))
	if err != nil || idx < 0 {
		return addrs[0], nil
	}
	return addrs[idx], nil
}

// cryptoRandIntn returns a uniform random int in [0, n) using crypto/rand.
func cryptoRandIntn(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("cryptoRandIntn: n must be positive")
	}
	// Rejection sampling over a 32-bit range for simplicity (n is small here).
	var buf [4]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, err
		}
		v := int(buf[0])<<24 | int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		// Map v into [0, n) without modulo bias.
		if v < (1<<32)-(1<<32)%n {
			return v % n, nil
		}
	}
}

// dialTimeout is a backstop for the direct-constraint host resolution, matching
// the spirit of the Rust flow (which relies on the system resolver's own
// timeout). Kept generous to avoid spurious failures on slow networks.
const dialResolveTimeout = 30 * time.Second
