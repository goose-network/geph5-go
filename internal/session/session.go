// Package session implements the geph5-client session manager, a port of
// binaries/geph5-client/src/session.rs.
//
// The session manager maintains a pool of TARGET_SESSION_COUNT (6) concurrent
// authenticated tunnels to the selected exit. Each tunnel is established by:
//
//  1. Compiling the exit route into a sillad.Dialer (internal/dialer).
//  2. Dialing a pre-authentication Pipe.
//  3. Running the exit handshake (client_auth): either a shared-secret
//     challenge (when the transport provides a shared secret, e.g. sosistab3)
//     or an X25519 key exchange signed by the exit's ed25519 key. The
//     handshake presents the client's connect token (level, ClientToken,
//     UnblindedSignature) as credentials.
//  4. Wrapping the authenticated pipe in picomux (internal/picomux) with
//     liveness ping_interval=1200s, timeout=120s, debloat=true.
//
// OpenConn selects a live session (round-robin, fewest pending opens), opens a
// picomux stream whose metadata is a RichTunnelCommand string, reads the
// 4-byte-BE-length-prefixed RichTunnelResponse, and returns the stream as a
// sillad.Pipe for the SOCKS5 / HTTP proxy servers.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/goose-network/geph5-go/internal/auth"
	"github.com/goose-network/geph5-go/internal/blake3"
	"github.com/goose-network/geph5-go/internal/brokerproto"
	"github.com/goose-network/geph5-go/internal/config"
	"github.com/goose-network/geph5-go/internal/database"
	"github.com/goose-network/geph5-go/internal/dialer"
	"github.com/goose-network/geph5-go/internal/exithandshake"
	"github.com/goose-network/geph5-go/internal/picomux"
	"github.com/goose-network/geph5-go/internal/sillad"
	"github.com/goose-network/geph5-go/internal/tunnelcmd"
	"golang.org/x/crypto/ed25519"
)

// targetSessionCount mirrors Rust TARGET_SESSION_COUNT.
const targetSessionCount = 6

// livenessPingInterval / livenessTimeout mirror Rust start_mux settings.
const (
	livenessPingInterval = 1200 * time.Second
	livenessTimeout      = 120 * time.Second
)

// dialThroughEstablishTimeout bounds the one-off chained session's establishment
// phase (conntest ping, client_auth handshake, mux metadata + tunnel open). Those
// steps read from the raw upstream transport, which does not watch ctx, so a
// silent c2e peer would otherwise hang the chained request indefinitely. The
// deadline is cleared once the tunnel is up so the proxied data path is unbounded.
const dialThroughEstablishTimeout = 30 * time.Second

// Manager owns the session pool and the machinery to establish authenticated
// tunnels to the exit. It is safe for concurrent use.
type Manager struct {
	cfg            *config.Config
	authMgr        *auth.Manager
	broker         *brokerproto.BrokerClient
	db             *database.Database
	brokerKeys     *dialer.BrokerKeys
	exitConstraint brokerproto.ExitConstraint
	allowDirect    bool
	sessMetadata   json.RawMessage
	// stackDialer, when non-nil, establishes the raw TCP connections to the
	// exit (see dialer.GetDialer); nil is the system dialer.
	stackDialer func(ctx context.Context, network, address string) (net.Conn, error)

	mu       sync.Mutex
	sessions []*sessionSlot
	// nextPick is the round-robin cursor for session selection.
	nextPick int
}

// sessionSlot holds one connected, authenticated, multiplexed session.
type sessionSlot struct {
	mux      *picomux.PicoMux
	exitInfo string                     // human-readable label for logging
	exitDesc brokerproto.ExitDescriptor // full exit descriptor (for conn_info)
	bridge   string                     // bridge SocketAddr string, "" if none
	// pendingOpens counts in-flight OpenConn calls using this session.
	pendingOpens int
	// dead is closed when the session's mux dies.
	dead chan struct{}
}

// NewManager constructs a session Manager bound to the given config, auth
// manager, broker client, and database. The auth manager supplies connect
// tokens; the broker client and database feed the route compiler.
// stackDialer, when non-nil, establishes the raw TCP connections to the exit
// (the embedding process's network stack); nil is the system dialer.
func NewManager(cfg *config.Config, authMgr *auth.Manager, broker *brokerproto.BrokerClient, db *database.Database, stackDialer func(ctx context.Context, network, address string) (net.Conn, error)) *Manager {
	m := &Manager{
		cfg:            cfg,
		authMgr:        authMgr,
		broker:         broker,
		db:             db,
		exitConstraint: brokerproto.AutoConstraint(),
		allowDirect:    false,
		stackDialer:    stackDialer,
	}
	if cfg != nil {
		m.exitConstraint = cfg.ExitConstraint
		m.allowDirect = cfg.AllowDirect
		m.sessMetadata = cfg.SessMetadata
		if cfg.BrokerKeys != nil {
			m.brokerKeys = &dialer.BrokerKeys{Master: cfg.BrokerKeys.Master}
		}
	}
	// Default unset session metadata to JSON null here, before any worker
	// goroutine exists. runSessionOnce and fetchDialer read sessMetadata
	// concurrently from the session workers without m.mu, so defaulting it
	// lazily there (as this used to) was a data race on the plain field.
	if len(m.sessMetadata) == 0 {
		m.sessMetadata = json.RawMessage("null")
	}
	return m
}

// AccountLevel reports the embedded auth manager's own account tier (per-client,
// not the process-global auth.ISPlus) and whether it is known yet. Embedders use
// it to gate exit eligibility by this client's credential. A nil auth manager
// (no broker) reports unknown.
func (m *Manager) AccountLevel() (isPlus bool, known bool) {
	if m.authMgr == nil {
		return false, false
	}
	return m.authMgr.AccountLevel()
}

// Run starts TARGET_SESSION_COUNT session workers plus a route-refresh
// goroutine, and blocks until ctx is canceled. Each worker maintains one
// tunnel with exponential backoff on failure.
func (m *Manager) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for i := 0; i < targetSessionCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			m.sessionWorker(ctx, id)
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.refreshLoop(ctx)
	}()
	wg.Wait()
	return ctx.Err()
}

// refreshLoop periodically re-runs GetDialer so the route cache stays fresh
// (mirrors the Rust refresh_get_dialer loop, 300..3600s).
func (m *Manager) refreshLoop(ctx context.Context) {
	for {
		secs := 300 + rand.Intn(3301) // 300..3600
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(secs) * time.Second):
		}
		if _, _, _, err := m.fetchDialer(ctx); err != nil {
			log.Printf("session: refresh get_dialer failed: %v", err)
		}
	}
}

// maxBackoffExponent clamps the session worker's 2^failures multiplier.
// failures is unbounded (it counts consecutive failures for the log line);
// shifting int64 by 63 wraps negative and by >= 64 yields 0, which collapsed
// the dial timeout and retry wait to <= 0 and spun the worker in a hot loop
// that no network recovery could break. 2^12 = 4096 already saturates the
// 120s caps (timeout base >= 30s; wait base >= 30ms), so the clamp only bites
// where the caps already dominate. Mirrors the clamped shift in
// meeklike/virta.go's retransmit backoff.
const maxBackoffExponent = 12

// backoffScale returns 2^min(failures, maxBackoffExponent) as a Duration
// multiplier, clamping the exponent BEFORE the shift so the product cannot
// overflow int64 nanoseconds.
func backoffScale(failures int) time.Duration {
	exponent := uint(failures)
	if exponent > maxBackoffExponent {
		exponent = maxBackoffExponent
	}
	return time.Duration(1 << exponent)
}

// sessionWorker maintains a single session with exponential backoff. Worker 0
// starts immediately; workers 1+ jitter 0..120s. On failure the wait time
// grows as rand(0..0.1)*2^min(failures,12) (capped 120s); the dial timeout grows
// as rand(30..60)*2^min(failures,12) (capped 120s).
func (m *Manager) sessionWorker(ctx context.Context, id int) {
	// Initial jitter for workers after the first.
	if id > 0 {
		jitter := time.Duration(rand.Intn(120)) * time.Second
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter):
		}
	}
	var failures int
	for {
		if ctx.Err() != nil {
			return
		}
		// Dial timeout scales with failures.
		timeoutSecs := 30 + rand.Intn(31) // 30..60
		timeout := time.Duration(timeoutSecs) * time.Second
		if failures > 0 {
			timeout *= backoffScale(failures)
			if timeout > 120*time.Second {
				timeout = 120 * time.Second
			}
		}
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		err := m.runSessionOnce(ctx, dialCtx, id)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			failures++
			log.Printf("session[%d]: failed: %v (failures=%d)", id, err, failures)
		} else {
			log.Printf("session[%d]: ended cleanly", id)
			failures = 0
		}
		// Backoff wait.
		wait := time.Duration(rand.Float64()*0.1*1000) * time.Millisecond
		if failures > 0 {
			wait *= backoffScale(failures)
			if wait > 120*time.Second {
				wait = 120 * time.Second
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// runSessionOnce establishes one session: get_dialer -> dial -> client_auth ->
// start_mux -> register -> proxy_loop. Blocks until the session dies.
//
// dialCtx bounds the establishment phase (get_dialer, dial, client_auth) only;
// once the session is up, it lives until the mux dies or ctx (the manager's
// lifetime) is canceled — the dial deadline must not become a session
// lifetime, or every healthy tunnel would be torn down after 30–60s.
func (m *Manager) runSessionOnce(ctx, dialCtx context.Context, id int) error {
	exitPubkey, exitDesc, dial, err := m.fetchDialer(dialCtx)
	if err != nil {
		return fmt.Errorf("get_dialer: %w", err)
	}
	// Dial with the remaining time on dialCtx.
	pipe, err := dial.Dial(dialCtx)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	// Authenticate.
	authedPipe, err := m.clientAuth(dialCtx, pipe, exitPubkey)
	if err != nil {
		pipe.Close()
		return fmt.Errorf("client_auth: %w", err)
	}
	// Start mux.
	mux := picomux.New(authedPipe)
	mux.SetLiveness(picomux.LivenessConfig{
		PingInterval: livenessPingInterval,
		Timeout:      livenessTimeout,
	})
	mux.SetDebloat(true)
	// Register the session metadata (Rust: "we first register the session
	// metadata" — the first JSON-metadata stream on each session). The exit
	// only accepts tunnel-command streams once this is registered; without it
	// the first tunnel open would be swallowed as metadata. The null default
	// is applied in NewManager so this is a plain read of an immutable field.
	if metaStream, err := mux.Open(m.sessMetadata); err == nil {
		// The exit reads and discards the metadata stream; close ours so its
		// handler completes instead of lingering.
		metaStream.Close()
	}
	// Register the session.
	label := fmt.Sprintf("exit %s (%s)", exitDesc.Country, exitDesc.C2EListen)
	slot := m.registerSession(mux, label, exitDesc, "")
	defer m.unregisterSession(slot)
	log.Printf("session[%d]: connected to %s", id, label)
	// proxy_loop: block until the mux dies. WaitUntilDead blocks until the
	// mux's read/ping loop observes a fatal error, so run it on a goroutine
	// and select between that and ctx cancellation.
	deadCh := make(chan struct{})
	go func() {
		_ = mux.WaitUntilDead()
		close(deadCh)
	}()
	select {
	case <-ctx.Done():
		mux.Close()
		return ctx.Err()
	case <-deadCh:
		return errors.New("mux died")
	}
}

// exitRouteClientMetadata is the client_metadata sent to broker.get_exit_route.
// Rust's get_device_metadata always sends at least {"version": CARGO_PKG_VERSION}
// (never bare null); the broker gates meeklike race routes on version >=0.2.72
// and reads ip_addr for ASN/country bridge tuning. We send the port's version
// (the geph5 workspace is 0.4.0) so the broker compiles the same route tree it
// gives a real client. This is DISTINCT from sessMetadata, which is the mux
// metadata stream opened at session.go's mux.Open.
var exitRouteClientMetadata = json.RawMessage(`{"version":"0.4.0"}`)

// fetchDialer compiles the exit route into a dialer, returning the exit's
// ed25519 public key, its descriptor, and a sillad.Dialer. It supplies the
// connect token (for the broker's get_exit_route args) when available.
func (m *Manager) fetchDialer(ctx context.Context) (exitPubkey []byte, exit brokerproto.ExitDescriptor, dial sillad.Dialer, err error) {
	args := brokerproto.GetExitRouteArgs{
		ExitConstraint: m.exitConstraint,
		ClientMetadata: exitRouteClientMetadata,
	}
	// Attach the connect token + signature if the auth manager has one. When
	// auth is not ready this leaves Token/Sig nil; fetchFreshExitRoute then
	// aborts the fresh fetch (never sending null token/sig to the broker) and
	// GetDialer falls back to the cached route, matching Rust's get_dialer.
	if m.authMgr != nil {
		if ct, tokErr := m.authMgr.GetConnectToken(ctx); tokErr == nil {
			tokenJSON, _ := json.Marshal(ct.Token) // ClientToken -> JSON byte array
			sigJSON, _ := json.Marshal(ct.Sig)     // UnblindedSignature -> serde JSON
			args.Token = tokenJSON
			args.Sig = sigJSON
		}
	}
	return dialer.GetDialer(ctx, m.exitConstraint, m.allowDirect, m.brokerKeys, m.broker, m.db, args, m.stackDialer)
}

// clientAuth runs the exit handshake. If the transport pipe carries a shared
// secret (SharedSecret() != nil), it uses a shared-secret challenge;
// otherwise it does a full X25519 key exchange and verifies the exit's
// ed25519 signature. On success it returns a sillad.Pipe ready to be wrapped
// in picomux: the shared-secret path returns the transport pipe unchanged
// (the transport already encrypts), while the X25519 path wraps the pipe in
// a ClientCryptPipe (ChaCha20Poly1305 record framing, a sillad.Pipe/net.Conn).
func (m *Manager) clientAuth(ctx context.Context, pipe sillad.Pipe, exitPubkey []byte) (sillad.Pipe, error) {
	// Build the credentials blob: stdcode(level, token, sig), or empty if no
	// broker / connect token.
	var credentials []byte
	if m.authMgr != nil {
		if ct, err := m.authMgr.GetConnectToken(ctx); err == nil {
			if b, err := ct.MarshalStdcode(); err == nil {
				credentials = b
			}
		}
	}

	sharedSecret := pipe.SharedSecret()

	if len(sharedSecret) > 0 {
		// Shared-secret challenge path.
		return m.sharedSecretAuth(pipe, sharedSecret, credentials)
	}
	// X25519 path.
	if len(exitPubkey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("client_auth: bad exit pubkey length %d", len(exitPubkey))
	}
	return m.x25519Auth(pipe, credentials, exitPubkey)
}

// sharedSecretAuth performs the shared-secret challenge handshake:
//
//   - ClientHello{credentials, SharedSecretChallenge(random 32 bytes)}.
//   - Write 4-byte-BE-length-prefixed stdcode(ClientHello).
//   - Read 4-byte-BE-length-prefixed stdcode(ExitHello).
//   - Check inner.SharedSecretResponse == blake3::keyed_hash(challenge, shared_secret).
//
// On success the pipe is returned unwrapped (the transport already encrypts).
func (m *Manager) sharedSecretAuth(pipe sillad.Pipe, sharedSecret, credentials []byte) (sillad.Pipe, error) {
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, err
	}
	hello := exithandshake.ClientHello{
		Credentials: credentials,
		CryptHello: exithandshake.ClientCryptHello{
			Kind:      exithandshake.KindSharedSecret,
			Challenge: challenge,
		},
	}
	helloBytes, err := hello.MarshalStdcode()
	if err != nil {
		return nil, err
	}
	if err := writePrependLength(pipe, helloBytes); err != nil {
		return nil, fmt.Errorf("write client hello: %w", err)
	}
	respBytes, err := readPrependLength(pipe)
	if err != nil {
		return nil, fmt.Errorf("read exit hello: %w", err)
	}
	var exitHello exithandshake.ExitHello
	if err := exitHello.UnmarshalStdcode(respBytes); err != nil {
		return nil, fmt.Errorf("decode exit hello: %w", err)
	}
	if exitHello.Inner.Kind == exithandshake.InnerReject {
		return nil, fmt.Errorf("exit rejected: %s", exitHello.Inner.RejectReason)
	}
	if exitHello.Inner.Kind != exithandshake.InnerSharedSecretResponse {
		return nil, fmt.Errorf("exit hello: expected shared-secret response, got kind %d", exitHello.Inner.Kind)
	}
	// expected = blake3::keyed_hash(challenge, shared_secret)
	expected := blake3.KeyedHash(challenge, sharedSecret)
	if exitHello.Inner.MAC != expected {
		return nil, errors.New("client_auth: shared-secret challenge mismatch")
	}
	return pipe, nil
}

// x25519Auth performs the full X25519 handshake:
//
//   - ClientHello{credentials, X25519(ephemeral_pubkey)}.
//   - Write/read length-prefixed stdcode hellos.
//   - Verify the exit's ed25519 signature over stdcode((client_hello, exit_hello.inner))
//     using exitPubkey.
//   - Derive read_key = blake3::derive_key("e2c", shared), write_key = blake3::derive_key("c2e", shared).
//   - Wrap the pipe in a ChaCha20Poly1305 ClientCryptPipe (a sillad.Pipe/net.Conn).
func (m *Manager) x25519Auth(pipe sillad.Pipe, credentials, exitPubkey []byte) (sillad.Pipe, error) {
	myPriv, myPub, err := exithandshake.NewEphemeralKey()
	if err != nil {
		return nil, err
	}
	hello := exithandshake.ClientHello{
		Credentials: credentials,
		CryptHello: exithandshake.ClientCryptHello{
			Kind:      exithandshake.KindX25519,
			X25519Pub: myPub,
		},
	}
	helloBytes, err := hello.MarshalStdcode()
	if err != nil {
		return nil, err
	}
	if err := writePrependLength(pipe, helloBytes); err != nil {
		return nil, fmt.Errorf("write client hello: %w", err)
	}
	respBytes, err := readPrependLength(pipe)
	if err != nil {
		return nil, fmt.Errorf("read exit hello: %w", err)
	}
	var exitHello exithandshake.ExitHello
	if err := exitHello.UnmarshalStdcode(respBytes); err != nil {
		return nil, fmt.Errorf("decode exit hello: %w", err)
	}
	if exitHello.Inner.Kind == exithandshake.InnerReject {
		return nil, fmt.Errorf("exit rejected: %s", exitHello.Inner.RejectReason)
	}
	if exitHello.Inner.Kind != exithandshake.InnerX25519 {
		return nil, fmt.Errorf("exit hello: expected X25519, got kind %d", exitHello.Inner.Kind)
	}
	// Verify the signature over stdcode((client_hello, exit_hello.inner)).
	// The signed message is the concatenation of the ClientHello stdcode
	// bytes and the ExitHelloInner stdcode bytes.
	innerBytes, err := exitHello.Inner.MarshalStdcode()
	if err != nil {
		return nil, err
	}
	signedMsg := append(append([]byte{}, helloBytes...), innerBytes...)
	if !ed25519.Verify(ed25519.PublicKey(exitPubkey), signedMsg, exitHello.Signature[:]) {
		return nil, errors.New("client_auth: exit signature verification failed")
	}
	// Derive keys and wrap in ClientCryptPipe (a sillad.Pipe/net.Conn that
	// applies ChaCha20Poly1305 record framing over the underlying pipe).
	readKey, writeKey := exithandshake.DeriveKeys(myPriv, exitHello.Inner.X25519Pub)
	crypt, err := exithandshake.NewClientCryptPipe(pipe, readKey, writeKey)
	if err != nil {
		return nil, err
	}
	return crypt, nil
}

// registerSession adds a session slot to the pool and returns it.
func (m *Manager) registerSession(mux *picomux.PicoMux, label string, exitDesc brokerproto.ExitDescriptor, bridge string) *sessionSlot {
	slot := &sessionSlot{mux: mux, exitInfo: label, exitDesc: exitDesc, bridge: bridge, dead: make(chan struct{})}
	m.mu.Lock()
	m.sessions = append(m.sessions, slot)
	m.mu.Unlock()
	return slot
}

// unregisterSession removes a slot from the pool.
func (m *Manager) unregisterSession(slot *sessionSlot) {
	m.mu.Lock()
	for i, s := range m.sessions {
		if s == slot {
			m.sessions = append(m.sessions[:i], m.sessions[i+1:]...)
			break
		}
	}
	m.mu.Unlock()
}

// selectSession picks a live session using round-robin with a bias toward the
// fewest pending opens (mirrors Rust select_session). Returns nil if no live
// session is available.
func (m *Manager) selectSession() *sessionSlot {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Filter to alive sessions.
	var alive []*sessionSlot
	for _, s := range m.sessions {
		if s.mux.IsAlive() {
			alive = append(alive, s)
		}
	}
	if len(alive) == 0 {
		return nil
	}
	// Round-robin starting at nextPick, then prefer fewest pending opens.
	best := alive[m.nextPick%len(alive)]
	for _, s := range alive {
		if s.pendingOpens < best.pendingOpens {
			best = s
		}
	}
	m.nextPick++
	best.pendingOpens++
	return best
}

// OpenConn opens a tunneled connection to remote (a "host:port" string) over
// the given protocol ("tcp" or "udp"). It mirrors Rust session::open_conn.
func (m *Manager) OpenConn(ctx context.Context, protocol, remote string) (sillad.Pipe, error) {
	slot := m.selectSession()
	if slot == nil {
		return nil, errors.New("session: no live session available")
	}
	defer func() {
		m.mu.Lock()
		slot.pendingOpens--
		m.mu.Unlock()
	}()
	// Build the tunnel command string: RichTunnelCommand{protocol, host}.
	cmd := tunnelcmd.TunnelCommand{
		Kind:     tunnelcmd.KindRich,
		Protocol: protocol,
		Host:     remote,
	}
	cmdStr := cmd.String()
	stream, err := slot.mux.Open([]byte(cmdStr))
	if err != nil {
		return nil, fmt.Errorf("open tunnel: %w", err)
	}
	// Read the RichTunnelResponse (4-byte BE length prefix + JSON).
	resp, err := tunnelcmd.ReadTunnelResponse(stream)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("read tunnel response: %w", err)
	}
	if resp.Kind != tunnelcmd.KindSuccess {
		stream.Close()
		return nil, fmt.Errorf("tunnel open failed: %s", resp.Fail)
	}
	return newStreamPipe(stream, slot.exitInfo), nil
}

// OpenConnFunc is the function signature the proxy servers expect for opening
// a tunneled TCP connection: given a "host:port" string, return a connected
// net.Conn (the proxied byte stream).
type OpenConnFunc func(ctx context.Context, remote string) (net.Conn, error)

// AsOpenConnFunc adapts Manager.OpenConn to the OpenConnFunc signature the
// proxy servers use, restricting the protocol to "tcp" and unwrapping the
// sillad.Pipe (which is itself a net.Conn) for the caller.
func (m *Manager) AsOpenConnFunc() OpenConnFunc {
	return func(ctx context.Context, remote string) (net.Conn, error) {
		pipe, err := m.OpenConn(ctx, "tcp", remote)
		if err != nil {
			return nil, err
		}
		return pipe, nil
	}
}

// DialThrough establishes a ONE-OFF authenticated session over an existing
// transport conn (via) that already reaches the exit, then opens a tunneled
// stream to remote. It is the proxy-chaining entry point (the goose router's
// ChainDialer): the previous hop has already tunneled to the exit's c2e
// listener, so geph runs its route handshake (conntest ping, client_auth) and
// picomux over that tunnel instead of dialing the exit from the local network.
//
// Only a single-transport route is supported — a "direct" (pinned) exit
// constraint, which compiles to ConnTest{Tcp(c2e)}. A race/fallback/auto tree
// would dial the raw transport more than once and cannot ride a single via, so
// it is rejected. The route's own layers still run over via: the conntest ping
// is echoed by the exit, and client_auth does the X25519 exchange (the raw TCP
// transport carries no shared secret).
//
// Ownership: on success the returned conn owns via — closing it tears down the
// one-off mux and via. On error via is closed here (the router also closes the
// previous conn on a failed DialThrough; the double close is benign).
func (m *Manager) DialThrough(ctx context.Context, via net.Conn, protocol, remote string) (conn net.Conn, err error) {
	if m.exitConstraint.Kind != "direct" {
		return nil, fmt.Errorf("session: DialThrough requires a direct (pinned) exit constraint, got %q", m.exitConstraint.Kind)
	}
	defer func() {
		if err != nil {
			via.Close()
		}
	}()
	// Bound establishment so a silent c2e peer fails fast rather than hanging the
	// chained request forever: the conntest/auth/tunnel-open reads run on the raw
	// transport (and then the mux read loop feeding them), none of which watch
	// ctx. A deadline on via propagates to all of them. Honor a shorter ctx
	// deadline when present; cleared on success below so data is unbounded.
	establishDeadline := time.Now().Add(dialThroughEstablishTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(establishDeadline) {
		establishDeadline = d
	}
	_ = via.SetDeadline(establishDeadline)
	// The route's single raw TCP dial yields via; every higher layer (conntest,
	// and sosistab3/tls if a future direct route carried them) runs over it.
	viaDialer := func(context.Context, string, string) (net.Conn, error) { return via, nil }
	// A direct constraint is resolved client-side (getDialerDirect) and never
	// sent to the broker, so the connect token / signature are not needed here.
	args := brokerproto.GetExitRouteArgs{
		ExitConstraint: m.exitConstraint,
		ClientMetadata: exitRouteClientMetadata,
	}
	exitPubkey, _, dial, err := dialer.GetDialer(ctx, m.exitConstraint, m.allowDirect, m.brokerKeys, m.broker, m.db, args, viaDialer)
	if err != nil {
		return nil, fmt.Errorf("session: dial_through get_dialer: %w", err)
	}
	pipe, err := dial.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("session: dial_through dial: %w", err)
	}
	authedPipe, err := m.clientAuth(ctx, pipe, exitPubkey)
	if err != nil {
		return nil, fmt.Errorf("session: dial_through client_auth: %w", err)
	}
	mux := picomux.New(authedPipe)
	mux.SetLiveness(picomux.LivenessConfig{
		PingInterval: livenessPingInterval,
		Timeout:      livenessTimeout,
	})
	mux.SetDebloat(true)
	// Register the session metadata first (the exit only accepts tunnel-command
	// streams once it has read the metadata stream), exactly as runSessionOnce.
	if metaStream, e := mux.Open(m.sessMetadata); e == nil {
		metaStream.Close()
	}
	cmd := tunnelcmd.TunnelCommand{
		Kind:     tunnelcmd.KindRich,
		Protocol: protocol,
		Host:     remote,
	}
	stream, err := mux.Open([]byte(cmd.String()))
	if err != nil {
		return nil, fmt.Errorf("session: dial_through open tunnel: %w", err)
	}
	resp, err := tunnelcmd.ReadTunnelResponse(stream)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("session: dial_through read tunnel response: %w", err)
	}
	if resp.Kind != tunnelcmd.KindSuccess {
		stream.Close()
		return nil, fmt.Errorf("session: dial_through tunnel open failed: %s", resp.Fail)
	}
	// Establishment complete: clear the transport deadline so the proxied data
	// path is not bounded by the establishment timeout.
	_ = via.SetDeadline(time.Time{})
	// getDialerDirect returns a placeholder descriptor (Country "AW", C2EListen
	// "0.0.0.0:0"); label the session with the real pinned c2e from the direct
	// constraint ("host:port/pubkeyhex") instead.
	c2e := m.exitConstraint.Direct
	if i := strings.IndexByte(c2e, '/'); i >= 0 {
		c2e = c2e[:i]
	}
	label := fmt.Sprintf("exit %s (pinned)", c2e)
	log.Printf("session: dial_through connected to %s via upstream tunnel", label)
	return &oneShotStreamPipe{
		streamPipe: &streamPipe{Stream: stream, protocol: "picomux", remoteStr: label},
		mux:        mux,
	}, nil
}

// SendVPNPacket is a placeholder for the VPN packet pump. The full VPN
// pipeline is not ported; this exists so the stdio_vpn loop has a call site.
func (m *Manager) SendVPNPacket(packet []byte) error {
	_ = packet
	return errors.New("session: vpn packet pump not implemented")
}

// LiveSessionInfo describes a currently-connected session for the control
// protocol's conn_info report. Protocol is the tunnel protocol label
// (currently always "tcp"); Exit is the full exit descriptor; Bridge is the
// bridge SocketAddr string (nil if none).
type LiveSessionInfo struct {
	Protocol string
	Exit     brokerproto.ExitDescriptor
	Bridge   *string
}

// LiveSessionInfos returns a snapshot of the currently-alive sessions, for the
// control protocol's conn_info method. Mirrors the Rust
// CURRENT_CONNECTED_INFOS slab read. The returned slice is empty when no
// session is alive (which the control protocol maps to ConnInfo::Connecting).
func (m *Manager) LiveSessionInfos() []LiveSessionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []LiveSessionInfo
	for _, s := range m.sessions {
		if s.mux.IsAlive() {
			info := LiveSessionInfo{
				Protocol: "tcp",
				Exit:     s.exitDesc,
			}
			if s.bridge != "" {
				b := s.bridge
				info.Bridge = &b
			}
			out = append(out, info)
		}
	}
	return out
}
