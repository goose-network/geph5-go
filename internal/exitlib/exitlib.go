// Package exitlib implements the geph5 exit server — the c2e (client-to-exit)
// side of the protocol — as an embeddable library, mirroring the serving path
// of the Rust geph5-exit binary (binaries/geph5-exit/src/listen.rs +
// proxy.rs). Together with internal/clientlib it makes the full
// client→tunnel→exit chain runnable inside a single Go process.
//
// Per accepted c2e connection the exit speaks, in order:
//
//  1. The sillad-conntest echo protocol (2-byte BE u16 size, payload, echo,
//     terminated by a zero size) — the client's direct-route dialer always
//     pings once before handing the connection upstream.
//  2. The exit handshake: read_prepend_length(ClientHello) → X25519 → sign
//     stdcode((client_hello, exit_hello.inner)) with the exit's ed25519
//     signing key → write_prepend_length(ExitHello).
//  3. ChaCha20Poly1305 record framing (internal/exithandshake), server-side
//     key orientation: read_key = derive("c2e"), write_key = derive("e2c").
//  4. picomux (internal/picomux). The FIRST stream whose metadata parses as
//     JSON is swallowed as session metadata (the client always opens it
//     first); "!bw-accounting" streams are accepted and closed (this exit
//     never rate-limits); every other stream is a TunnelCommand.
//  5. Tunnel streams: parse the command, resolve the target (IP literals
//     short-circuit DNS, mirroring SocketAddr::from_str), enforce the allow
//     rules (port 25 ban + global routability, see allowRules), dial with a
//     5s timeout, reply with a rich RichTunnelResponse, then relay bytes.
//
// Deviations from the Rust exit, all of which are invisible on the wire for
// the supported paths: no broker/b2e listener (bridges need broker-side
// machinery; direct constraints never use them), no credential verification
// (mirroring a broker-less Rust exit, which uses RateLimiter::unlimited), no
// DNS filtering (nsfw/ads lists) and no IPv6 eyeball pool — the system
// resolver and a plain dialer are used instead; UDP tunnels are not proxied.
// The AllowLoopback option relaxes the loopback rejection that the Rust exit
// hard-codes; it exists for embedded/self-test use where the "internet" the
// exit reaches is a loopback server in the same process.
package exitlib

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/geph-official/geph5-go/internal/blake3"
	"github.com/geph-official/geph5-go/internal/exithandshake"
	"github.com/geph-official/geph5-go/internal/picomux"
	"github.com/geph-official/geph5-go/internal/sillad"
	"github.com/geph-official/geph5-go/internal/tunnelcmd"
)

// handshakeTimeout bounds the conntest + hello phase of a connection. The
// Rust exit applies no deadline, but a library that shares the process with
// its clients cannot leave a goroutine parked on a silent connection forever.
const handshakeTimeout = 60 * time.Second

// dialTimeout mirrors the 5s TCP-dial timeout in the Rust exit's open_tunnel.
const dialTimeout = 5 * time.Second

// Options configures an exit server.
type Options struct {
	// C2EListen is the address the c2e listener binds. Empty means
	// "127.0.0.1:0" (an ephemeral loopback port); the bound address is
	// reported by Exit.C2EAddr.
	C2EListen string

	// Seed is the ed25519 signing seed (exactly the semantics of the Rust
	// exit's signing_secret file: 32 bytes used as a SigningKey seed). The
	// zero value generates a fresh random key.
	Seed [32]byte

	// AllowLoopback bypasses the loopback rejection in the allow rules.
	// The Rust exit refuses non-globally-routable targets outright; this
	// escape hatch exists so an embedded exit can proxy to loopback servers
	// in the same process (self-tests, single-process deployments).
	AllowLoopback bool
}

// Exit is a running geph5 exit server. Use Close to stop it.
type Exit struct {
	ln            net.Listener
	key           ed25519.PrivateKey
	allowLoopback bool

	cancel  context.CancelFunc
	stopped chan struct{} // closed when the accept loop exits

	// conns tracks live client connections so Close can tear them down.
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// Start binds the c2e listener synchronously (bind errors fail Start) and
// begins serving clients in the background. The first client may still be
// handshaking when Start returns.
func Start(ctx context.Context, opts Options) (*Exit, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	listen := opts.C2EListen
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	seed := opts.Seed
	if seed == ([32]byte{}) {
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, fmt.Errorf("exitlib: generate signing seed: %w", err)
		}
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("exitlib: c2e listen %s: %w", listen, err)
	}
	ctx, cancel := context.WithCancel(ctx)
	e := &Exit{
		ln:            ln,
		key:           ed25519.NewKeyFromSeed(seed[:]),
		allowLoopback: opts.AllowLoopback,
		cancel:        cancel,
		stopped:       make(chan struct{}),
		conns:         make(map[net.Conn]struct{}),
	}
	go e.acceptLoop(ctx)
	return e, nil
}

// C2EAddr returns the address the c2e listener bound.
func (e *Exit) C2EAddr() string { return e.ln.Addr().String() }

// PubkeyHex returns the exit's ed25519 public key as hex — the value a client
// pins in an ExitConstraint::Direct "host:port/pubkeyhex" constraint.
func (e *Exit) PubkeyHex() string {
	pub, _ := e.key.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub)
}

// Close stops the listener, cancels the accept loop, and closes every live
// client connection. It does not wait for per-connection handler goroutines
// (they exit when their connection errors out).
func (e *Exit) Close() error {
	e.cancel()
	err := e.ln.Close()
	e.mu.Lock()
	for c := range e.conns {
		c.Close()
	}
	e.conns = make(map[net.Conn]struct{})
	e.mu.Unlock()
	<-e.stopped
	return err
}

func (e *Exit) acceptLoop(ctx context.Context) {
	defer close(e.stopped)
	for {
		conn, err := e.ln.Accept()
		if err != nil {
			return
		}
		e.mu.Lock()
		e.conns[conn] = struct{}{}
		e.mu.Unlock()
		go func() {
			defer func() {
				e.mu.Lock()
				delete(e.conns, conn)
				e.mu.Unlock()
				conn.Close()
			}()
			e.handleConn(ctx, conn)
		}()
	}
}

// handleConn serves one c2e connection: conntest echo, exit handshake, then
// the picomux tunnel loop. It returns when the connection dies.
func (e *Exit) handleConn(ctx context.Context, conn net.Conn) {
	// The handshake phase must not linger forever on a silent peer.
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := serveConnTest(conn); err != nil {
		return
	}
	crypt, err := e.handshake(conn)
	if err != nil {
		log.Printf("exitlib: handshake with %s failed: %v", conn.RemoteAddr(), err)
		return
	}
	// Clear the handshake deadline; the mux owns liveness from here on.
	_ = crypt.SetDeadline(time.Time{})

	mux := picomux.New(crypt)
	mux.SetDebloat(true)
	e.serveMux(mux)
}

// serveConnTest is the server side of the sillad-conntest protocol: echo each
// ping (2-byte BE u16 size + payload) back verbatim until the zero-size
// terminator.
func serveConnTest(conn net.Conn) error {
	for {
		var sizeBuf [2]byte
		if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
			return err
		}
		size := binary.BigEndian.Uint16(sizeBuf[:])
		if size == 0 {
			return nil
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return err
		}
		if _, err := conn.Write(payload); err != nil {
			return err
		}
	}
}

// handshake performs the server side of the exit handshake and returns the
// encrypted pipe the picomux runs over. It mirrors handle_client in
// listen.rs: X25519 against the client's ephemeral key, the ExitHello signed
// over stdcode((client_hello, exit_hello.inner)), credentials accepted
// unverified (this exit has no broker, exactly like a broker-less Rust exit).
func (e *Exit) handshake(conn net.Conn) (net.Conn, error) {
	helloBytes, err := readPrependLength(conn)
	if err != nil {
		return nil, fmt.Errorf("read client hello: %w", err)
	}
	var hello exithandshake.ClientHello
	if err := hello.UnmarshalStdcode(helloBytes); err != nil {
		return nil, fmt.Errorf("decode client hello: %w", err)
	}

	var inner exithandshake.ExitHelloInner
	var readKey, writeKey [32]byte
	switch hello.CryptHello.Kind {
	case exithandshake.KindSharedSecret:
		// The shared-secret variant requires the transport itself to carry a
		// secret (sosistab3); a direct c2e TCP connection has none, and the
		// Rust exit errors out of handle_client here too.
		return nil, errors.New("no shared secret on a direct c2e connection")
	case exithandshake.KindX25519:
		myPriv, myPub, err := exithandshake.NewEphemeralKey()
		if err != nil {
			return nil, err
		}
		shared, err := curve25519.X25519(myPriv[:], hello.CryptHello.X25519Pub[:])
		if err != nil {
			return nil, fmt.Errorf("x25519: %w", err)
		}
		// Server orientation, reversed from the client: the exit decrypts
		// c2e traffic and encrypts e2c traffic.
		readKey = blake3.DeriveKey("c2e", shared)
		writeKey = blake3.DeriveKey("e2c", shared)
		inner = exithandshake.ExitHelloInner{Kind: exithandshake.InnerX25519, X25519Pub: myPub}
	default:
		return nil, fmt.Errorf("unknown ClientCryptHello kind %d", hello.CryptHello.Kind)
	}

	innerBytes, err := inner.MarshalStdcode()
	if err != nil {
		return nil, err
	}
	// The signature covers stdcode((client_hello, exit_hello.inner)) — the
	// tuple encoding is the concatenation of the two encodings.
	signedMsg := append(append([]byte{}, helloBytes...), innerBytes...)
	exitHello := exithandshake.ExitHello{Inner: inner}
	copy(exitHello.Signature[:], ed25519.Sign(e.key, signedMsg))
	respBytes, err := exitHello.MarshalStdcode()
	if err != nil {
		return nil, err
	}
	if err := writePrependLength(conn, respBytes); err != nil {
		return nil, fmt.Errorf("write exit hello: %w", err)
	}

	// Wrap the connection in the record framing (server key orientation:
	// readKey decrypts c2e, writeKey encrypts e2c). The crypt pipe is a
	// sillad.Pipe (hence a net.Conn) suitable for picomux.
	connPipe := &sillad.ConnPipe{
		Conn:        conn,
		ProtocolStr: "plain",
		RemoteStr:   conn.RemoteAddr().String(),
	}
	return exithandshake.NewClientCryptPipe(connPipe, readKey, writeKey)
}

// serveMux runs the per-session stream loop: the first JSON-metadata stream
// is swallowed (session metadata), "!bw-accounting" streams are closed (this
// exit is unlimited), and everything else is a tunnel command.
func (e *Exit) serveMux(mux *picomux.PicoMux) {
	sessMetadataSeen := false
	for {
		stream, err := mux.Accept()
		if err != nil {
			return
		}
		metadata := string(stream.Metadata())
		if !sessMetadataSeen && json.Valid([]byte(metadata)) {
			// The first JSON stream sets session metadata; the exit discards
			// it. Rich tunnel commands are JSON too, so only the FIRST one
			// is treated as metadata (the client opens the metadata stream
			// before any tunnel).
			sessMetadataSeen = true
			stream.Close()
			continue
		}
		switch metadata {
		case "!bw-accounting", "!bw-accounting-2":
			// The Rust exit runs a bandwidth-accounting loop here. This exit
			// has no rate limiter (broker-less = unlimited), so the stream
			// has nothing to carry; accept and close it.
			stream.Close()
			continue
		}
		go e.serveTunnel(stream)
	}
}

// serveTunnel handles one tunnel stream: parse the command, open the tunnel,
// reply (rich commands only), and relay bytes until either side finishes.
// Mirrors proxy_stream + open_tunnel + proxy_tcp in proxy.rs.
func (e *Exit) serveTunnel(stream *picomux.Stream) {
	cmd, err := tunnelcmd.ParseTunnelCommand(string(stream.Metadata()))
	if err != nil {
		// Not even parseable as a command; the Rust proxy_stream errors out
		// before knowing whether the command was rich, so no reply either.
		stream.Close()
		return
	}
	isRich := cmd.IsRich()
	conn, openMs, err := e.dialTunnel(cmd)
	if err != nil {
		if isRich {
			_ = tunnelcmd.WriteTunnelResponse(stream, tunnelcmd.FailResponse(err.Error()))
		}
		stream.Close()
		return
	}
	if isRich {
		resp := tunnelcmd.SuccessResponse(conn.RemoteAddr().String(), &openMs)
		if err := tunnelcmd.WriteTunnelResponse(stream, resp); err != nil {
			conn.Close()
			stream.Close()
			return
		}
	}
	// Bidirectional relay; the first direction to finish wins (the Rust
	// proxy_tcp races the two copies).
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(conn, stream)
		conn.Close()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(stream, conn)
		stream.Close()
		done <- struct{}{}
	}()
	<-done
}

// dialTunnel resolves and dials the command's target. It returns the
// connected net.Conn and the dial latency in milliseconds.
func (e *Exit) dialTunnel(cmd tunnelcmd.TunnelCommand) (net.Conn, uint32, error) {
	if protocol := cmd.ProtocolOf(); protocol != "tcp" {
		return nil, 0, fmt.Errorf("unknown protocol %s", protocol)
	}
	host := cmd.HostOf()
	addrs, err := resolveAddrs(host)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to resolve DNS: %w", err)
	}
	for _, a := range addrs {
		if a.port == 25 {
			return nil, 0, errors.New("Proxying to port 25 is not allowed")
		}
	}
	for _, a := range addrs {
		if !isGloballyRoutable(a.ip, a.v6Form, e.allowLoopback) {
			return nil, 0, fmt.Errorf("Proxying to %s is not allowed", host)
		}
	}
	start := time.Now()
	var lastErr error
	for _, a := range addrs {
		d := net.Dialer{Timeout: dialTimeout}
		conn, derr := d.Dial("tcp", net.JoinHostPort(a.ip.String(), strconv.Itoa(a.port)))
		if derr == nil {
			return conn, uint32(time.Since(start).Milliseconds()), nil
		}
		lastErr = derr
	}
	return nil, 0, fmt.Errorf("timeout in TCP dial to %v: %w", addrs, lastErr)
}

// resolvedAddr is one resolution result, carrying the address family as the
// target was written: a bracketed IPv6 literal (even an IPv4-mapped one)
// keeps v6Form=true, exactly like Rust's IpAddr::V6 from
// SocketAddr::from_str("[::ffff:127.0.0.1]:port"); dotted-quad literals and
// A-record lookups are v4Form. The family must ride alongside the IP because
// net.ParseIP represents "127.0.0.1" and "::ffff:127.0.0.1" identically.
type resolvedAddr struct {
	ip     net.IP
	port   int
	v6Form bool
}

func (a resolvedAddr) String() string {
	return net.JoinHostPort(a.ip.String(), strconv.Itoa(a.port))
}

// resolveAddrs mirrors dns_resolve: a name that parses as a SocketAddr
// ("ip:port" or bracketed IPv6) is returned as-is with no DNS; anything else
// is resolved through the system resolver. An IPv6 literal keeps v6Form=true
// (IPv4-mapped literals included — the allow rules must judge them by the
// IPv6 predicates, like Rust); DNS results are v4Form when To4() is non-nil
// (A records — and, degenerately, mapped AAAA answers, matching the A-record
// treatment Rust gives them).
func resolveAddrs(name string) ([]resolvedAddr, error) {
	if host, portStr, err := net.SplitHostPort(name); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			if port, err := strconv.Atoi(portStr); err == nil {
				return []resolvedAddr{{ip: ip, port: port, v6Form: strings.Contains(host, ":")}}, nil
			}
		}
	}
	host, portStr, err := net.SplitHostPort(name)
	if err != nil {
		return nil, fmt.Errorf("could not split into host:port: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("bad port %q: %w", portStr, err)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no addrs")
	}
	addrs := make([]resolvedAddr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, resolvedAddr{ip: ip, port: port, v6Form: ip.To4() == nil})
	}
	return addrs, nil
}

// isGloballyRoutable mirrors allow.rs: an address is proxyable when it is
// globally routable, with the loopback predicates optionally bypassed
// (AllowLoopback). v6Form selects the predicate family: the IPv4 check
// applies to dotted-quad targets; a bracketed IPv6 target — including an
// IPv4-mapped literal — goes through the IPv6 predicates, which do not reject
// the mapped form (exactly how the Rust exit's IpAddr::V6 branch treats
// "::ffff:a.b.c.d").
func isGloballyRoutable(ip net.IP, v6Form, allowLoopback bool) bool {
	if v6Form {
		v6 := ip.To16()
		if v6 == nil {
			return false
		}
		var b [16]byte
		copy(b[:], v6)
		return isIPv6GloballyRoutable(b, allowLoopback)
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return isIPv4GloballyRoutable([4]byte{v4[0], v4[1], v4[2], v4[3]}, allowLoopback)
}

func isIPv4GloballyRoutable(o [4]byte, allowLoopback bool) bool {
	if !allowLoopback && o[0] == 127 {
		return false // is_loopback
	}
	if o[0] == 10 || (o[0] == 172 && o[1]&0xf0 == 16) || (o[0] == 192 && o[1] == 168) {
		return false // is_private
	}
	if o[0] == 169 && o[1] == 254 {
		return false // is_link_local
	}
	if o[0] == 255 && o[1] == 255 && o[2] == 255 && o[3] == 255 {
		return false // is_broadcast
	}
	if (o[0] == 192 && o[1] == 0 && o[2] == 2) ||
		(o[0] == 198 && o[1] == 51 && o[2] == 100) ||
		(o[0] == 203 && o[1] == 0 && o[2] == 113) {
		return false // is_documentation
	}
	if o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] == 0 {
		return false // is_unspecified
	}
	if o[0] == 100 && o[1]&0xc0 == 0x40 {
		return false // shared address space 100.64/10
	}
	if o[0] == 192 && o[1] == 0 && o[2] == 0 {
		return false // IETF protocol assignments 192.0.0.0/24
	}
	if o[0]&0xf0 == 0xf0 && !(o[0] == 255 && o[1] == 255 && o[2] == 255 && o[3] == 255) {
		return false // reserved 240/4
	}
	if o[0] == 198 && o[1]&0xfe == 18 {
		return false // benchmarking 198.18.0.0/15
	}
	return true
}

func isIPv6GloballyRoutable(b [16]byte, allowLoopback bool) bool {
	if !allowLoopback && isIPv6Loopback(b) {
		return false
	}
	if isIPv6Unspecified(b) {
		return false
	}
	if b[0] == 0xff {
		return false // multicast
	}
	if b[0]&0xfe == 0xfc {
		return false // unique local fc00::/7
	}
	if b[0] == 0xfe && b[1]&0xc0 == 0x80 {
		return false // link local fe80::/10
	}
	return true
}

func isIPv6Loopback(b [16]byte) bool {
	for i := 0; i < 15; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return b[15] == 1
}

func isIPv6Unspecified(b [16]byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// readPrependLength mirrors geph5_misc_rpc::read_prepend_length: a 4-byte
// big-endian u32 length prefix followed by that many bytes, capped at 100KB.
func readPrependLength(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > 100*1024 {
		return nil, fmt.Errorf("exitlib: message too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writePrependLength mirrors geph5_misc_rpc::write_prepend_length.
func writePrependLength(w io.Writer, payload []byte) error {
	if len(payload) > 100*1024 {
		return fmt.Errorf("exitlib: payload too large: %d", len(payload))
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
