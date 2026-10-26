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
	"sync"
	"time"

	"github.com/geph-official/geph5-go/internal/auth"
	"github.com/geph-official/geph5-go/internal/blake3"
	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/config"
	"github.com/geph-official/geph5-go/internal/database"
	"github.com/geph-official/geph5-go/internal/dialer"
	"github.com/geph-official/geph5-go/internal/exithandshake"
	"github.com/geph-official/geph5-go/internal/picomux"
	"github.com/geph-official/geph5-go/internal/sillad"
	"github.com/geph-official/geph5-go/internal/tunnelcmd"
	"golang.org/x/crypto/ed25519"
)

// targetSessionCount mirrors Rust TARGET_SESSION_COUNT.
const targetSessionCount = 6

// livenessPingInterval / livenessTimeout mirror Rust start_mux settings.
const (
	livenessPingInterval = 1200 * time.Second
	livenessTimeout      = 120 * time.Second
)

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

// sessionWorker maintains a single session with exponential backoff. Worker 0
// starts immediately; workers 1+ jitter 0..120s. On failure the wait time
// grows as rand(0..0.1)*2^failures (capped 120s); the dial timeout grows as
// rand(30..60)*2^failures (capped 120s).
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
			scale := time.Duration(1 << uint(failures))
			timeout *= scale
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
			scale := time.Duration(1 << uint(failures))
			wait *= scale
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

// fetchDialer compiles the exit route into a dialer, returning the exit's
// ed25519 public key, its descriptor, and a sillad.Dialer. It supplies the
// connect token (for the broker's get_exit_route args) when available.
func (m *Manager) fetchDialer(ctx context.Context) (exitPubkey []byte, exit brokerproto.ExitDescriptor, dial sillad.Dialer, err error) {
	args := brokerproto.GetExitRouteArgs{
		ExitConstraint: m.exitConstraint,
		ClientMetadata: m.sessMetadata,
	}
	// Attach the connect token + signature if the auth manager has one.
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
