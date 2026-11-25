// Package geph is the Geph outbound provider plugin for the goose proxy-pool
// engine (github.com/goose-network/goose). It embeds the geph5-go client — a
// wire-compatible Go port of the geph5 client core — as a library and exposes
// it to goose the same way the Tor provider embeds tor-go: the provider boots
// the full geph5 client (auth loop, session manager with its 6 concurrent
// tunnels) in the background, and once at least one session to a geph5 exit
// is live, it emits ONE goose outbound of protocol "geph". A dial through
// that outbound is an in-process call into the client — the outbound invokes
// the session manager's open-conn path directly — so there is no SOCKS/HTTP
// hop between goose and the embedded client; the client binds no listener at
// all.
//
// The client's own TCP dials through the engine, split by role. The control
// plane — the broker RPCs (including domain-fronted ones) that fetch the exit
// roster, auth tokens, and exit routes — rides the provider spec's
// upstream_proxy when it names a goose route (outbound:/pool:/chain:): the
// engine injects its route dialer (goose-plugin-api's UpstreamDialer) and the
// plugin hands it to clientlib as Options.BrokerDialer, so only the
// server-list fetches ride that outbound/pool/chain. The data path — the
// compiled route tree to the exit (sosistab3, plain TLS, meeklike, TCP
// hops), including every pinned per-exit client — never rides the provider
// upstream: it uses the engine's stack dialer (StackDialer — layer 2/3/4,
// system kernel or gvisor netstack) injected under pub.StackDialerKey, handed
// to clientlib as Options.StackDialer, or the system dialer when none is
// injected. Without an upstream route the broker fetches ride the stack
// dialer too.
//
// This package lives inside the geph5-go module (not a separate repo) because
// it embeds geph5-go's internal packages (internal/clientlib → internal/auth,
// internal/session, ...), which Go's internal-package rule confines to this
// module — the same arrangement as tor-go's plugins/tor. It imports only
// goose-plugin-api on the goose side, preserving the plugin import boundary:
// a plugin imports the contract module, never goose itself.
//
// # Bootstrap lifecycle
//
// Establishing a geph5 session means compiling an exit route, dialing the
// exit, completing the X25519+ed25519 handshake, and registering the
// tunnel — all work the session manager does on its own schedule once started.
// The provider therefore starts the client in a background goroutine from the
// factory and, independently of session readiness, polls the broker's net
// status for the exit roster: Outbounds advertises one outbound per discovered
// exit as soon as the roster arrives (the geph analogue of psiphon's datastore
// server list), and adds the general "geph" outbound once a live session
// exists. Each change signals Watch so the engine repolls promptly instead of
// waiting for the 2-minute fallback poll. A failed session (broker unreachable,
// exit down, or no credential) is retried indefinitely inside the session
// manager's workers, so the provider has no terminal error path except an
// invalid config, which fails the factory immediately.
//
// # Zero-config defaults
//
// With no config_path, embedded_exit, or inline exit_constraint/broker, the
// provider embeds the production geph5 network parameters (the auto exit
// constraint, the direct broker https://broker.geph.io, and its verification
// keys — see defaults.go) so it retrieves the live exit roster out of the box,
// exactly as the psiphon plugin downloads its signed server list with no
// operator-supplied file. Retrieving the roster needs no account; establishing
// a tunnel session does (geph is freemium), so a credential remains
// operator-supplied for traffic while the server list is discovered zero-config.
//
// # Config
//
// The provider config is a JSON object whose keys overlap the geph5 client
// config where they make sense as provider knobs:
//
//	{
//	  "config_path":  "/path/to/geph5.yaml",     // optional: full client YAML
//	                                             // (config.LoadYAML format)
//	  "embedded_exit": true,                     // run the exit in-process
//	  "outbound_id":  "geph",                    // goose outbound id
//	  "exit_constraint": {"direct": "host:port/<exit-pubkey-hex>"},
//	  "credentials":  "test_dummy",              // credential (see
//	  "secret":      "...",                     //  config.Credential;
//	  "username"/"password": "...",             //  only used with a broker)
//	  "cache":       "/path/to/db",              // persistent cache (default
//	                                             //  in-memory)
//	  "broker":      "https://...  or {...}",   // broker source (optional;
//	                                             //  direct-constraint setups
//	                                             //  don't need one)
//	  "broker_keys": {"master": "<hex>", ...}    // broker verification keys
//	}
//
// "config_path" loads the full client YAML; the inline keys (when present)
// are applied on top, so a static YAML can be reused while the plugin
// overrides the exit constraint.
//
// # Standalone mode (embedded exit)
//
// Setting "embedded_exit" boots a geph5 exit server (internal/exitlib, a Go
// port of the Rust geph5-exit serving path) inside the provider's own
// process and pins the client at it with an auto-generated direct
// constraint, overriding any configured exit_constraint. The whole chain —
// goose engine, geph client, geph exit — then runs in ONE process with no
// Rust binary, no broker, and no second process. This is the deployment
// shape for self-contained single-box setups (and the plugin's standalone
// test). "embedded_exit" accepts true or an object:
//
//	{ "listen": "127.0.0.1:0", "allow_loopback": true, "seed_hex": "<64 hex>" }
//
// "allow_loopback" relaxes the exit's global-routability rules so it will
// proxy to loopback targets in the same process — normally the exit refuses
// them exactly like the Rust one; "seed_hex" pins the exit's ed25519
// signing seed (otherwise a fresh key is generated per boot).
package geph

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net"
	"sort"
	"sync"
	"time"

	pub "github.com/goose-network/goose-plugin-api"

	"github.com/goose-network/geph5-go/internal/brokerproto"
	"github.com/goose-network/geph5-go/internal/clientlib"
	"github.com/goose-network/geph5-go/internal/config"
	"github.com/goose-network/geph5-go/internal/exitlib"
)

func init() {
	pub.RegisterProvider("geph", NewProvider)
	// Zero-config: the embedded production broker/keys retrieve the exit
	// roster with an empty config map, so the engine auto-seeds a geph
	// provider — it appears in the admin UI without operator setup.
	pub.RegisterDefaultProvider(pub.DefaultProvider{Provider: "geph"})
}

// liveProviders holds the running geph providers keyed by their contributed
// outbound id, mirroring plugins/tor. The "geph" outbound protocol resolves
// its tunnel at dial time through this table, so the emitted outbound config
// needs no addresses and stays valid across provider restarts: an old
// instance's Close uses CompareAndDelete, so it never clobbers a newer
// provider registered under the same id (the engine enforces unique outbound
// ids, so the key is unambiguous).
var liveProviders sync.Map // map[string]*Provider

func registerLiveProvider(p *Provider)   { liveProviders.Store(p.cfg.OutboundID, p) }
func unregisterLiveProvider(p *Provider) { liveProviders.CompareAndDelete(p.cfg.OutboundID, p) }
func lookupLiveProvider(id string) (*Provider, bool) {
	v, ok := liveProviders.Load(id)
	if !ok {
		return nil, false
	}
	p, ok := v.(*Provider)
	return p, ok
}

// clientConn is the clientlib.Client surface the provider needs: dialing in
// process, session counting, and shutdown. *clientlib.Client implements it;
// the interface keeps the dial path testable without booting a full session
// stack (mirroring plugins/tor's streamDialer seam).
type clientConn interface {
	OpenConn(ctx context.Context, remote string) (net.Conn, error)
	SessionCount() int
	Close()
}

// exitInfo is one broker-known exit, in the form the provider emits and the
// web UI shows. Hostname (the roster's pubkey-hex key) identifies the exit a
// per-exit dial pins via its c2e/pubkey "direct" constraint; C2EListen is the
// exit's client-facing host:port, appended to the per-exit outbound id.
// AllowedLevels is the exit's access policy from the broker roster ("Free",
// "Plus"): a free account can only tunnel through exits that admit "Free", so
// the provider advertises and dials per-exit outbounds accordingly. Empty means
// the roster carried no policy (legacy/unknown) — treated as usable.
type exitInfo struct {
	Hostname      string
	PubkeyHex     string
	C2EListen     string
	Country       string
	City          string
	AllowedLevels []string
}

// exitUsable reports whether an exit admits the account's current level. An
// exit with no advertised levels (unknown/legacy roster) is always usable, so
// missing metadata never silently narrows discovery. A free account (isPlus
// false) needs "Free" among the levels; a Plus account needs "Plus".
func exitUsable(levels []string, isPlus bool) bool {
	if len(levels) == 0 {
		return true
	}
	want := "Free"
	if isPlus {
		want = "Plus"
	}
	for _, l := range levels {
		if l == want {
			return true
		}
	}
	return false
}

// accountLevelName renders the account tier for diagnostics.
func accountLevelName(isPlus bool) string {
	if isPlus {
		return "Plus"
	}
	return "Free"
}

// accountLeveler is the optional capability a clientConn exposes when it can
// report its own account tier (the real *clientlib.Client does; test fakes need
// not). Reading the per-client tier — rather than the process-global
// auth.ISPlus that every embedded client overwrites — keeps each provider's
// exit-eligibility gate tied to its OWN credential.
type accountLeveler interface {
	AccountLevel() (isPlus bool, known bool)
}

// accountLevel reads THIS provider's primary client's own account tier. known
// is false when there is no client yet or its first auth has not completed;
// callers must not gate on tier then, or a cold Plus account would be misread as
// Free. All of a provider's clients share its credential, so the primary's tier
// represents the per-exit clients too.
func (p *Provider) accountLevel() (isPlus bool, known bool) {
	p.mu.Lock()
	c := p.client
	p.mu.Unlock()
	if al, ok := c.(accountLeveler); ok {
		return al.AccountLevel()
	}
	return false, false
}

// checkExitTier returns an actionable error when THIS provider's account cannot
// tunnel through an exit advertising the given levels. It gates on the
// per-client tier (not the process-global auth.ISPlus, which other providers
// overwrite) and only once the tier is known — during warmup a cold Plus account
// must not be misread as Free, so an unknown tier never rejects. The message
// names the exit's actual allowed levels and the account's actual tier, so it is
// correct for any mismatch (a Plus account on a Free-only exit included).
func (p *Provider) checkExitTier(hostname string, levels []string) error {
	isPlus, known := p.accountLevel()
	if known && !exitUsable(levels, isPlus) {
		return fmt.Errorf("geph provider: exit %s admits levels %v; this account is %s", hostname, levels, accountLevelName(isPlus))
	}
	return nil
}

// exitLevels returns the advertised allowed levels for a roster exit, or nil
// when the hostname is not in the current roster (exitUsable treats nil as
// unrestricted, so an unknown exit passes the tier gate and then fails the
// roster lookup in startExitClient). Read under p.mu; getOrStartExitClient uses
// it to re-check tier on every dial, not only when a per-exit client boots.
func (p *Provider) exitLevels(hostname string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.exits {
		if e.Hostname == hostname {
			return e.AllowedLevels
		}
	}
	return nil
}

// exitIdleClose bounds how long a lazily-started per-exit client with no
// traffic is kept before it is torn down again (a full session stack costs
// 6 tunnels and an auth loop; pinning 20 exits should not hold 20 stacks
// forever).
const exitIdleClose = 10 * time.Minute

// exitWaitSession bounds how long a dial waits for a freshly started per-exit
// client's first session before failing (the engine retries the dial; the
// client keeps establishing in the background).
const exitWaitSession = 2 * time.Minute

// Provider is a goose outbound provider backed by an embedded geph5 client.
// It implements pub.Provider and pub.StatusReporter.
type Provider struct {
	cfg providerConfig

	// client state, guarded by mu
	mu       sync.Mutex
	ready    bool          // a live session tunnel exists
	startErr error         // terminal startup error, surfaced via Outbounds
	client   clientConn    // the embedded client (dials in process; no listener)
	exit     *exitlib.Exit // non-nil in standalone (embedded_exit) mode
	exits    []exitInfo    // broker-known exits (per-exit outbound source)
	// exitClients holds one lazily-started embedded client per pinned exit
	// hostname; reapExitClients drops clients whose last dial is older than
	// exitIdleClose.
	exitClients map[string]*exitClientState
	// exitCancels collects the cancel funcs of per-exit clients so Close stops
	// them with the provider (their Close call alone does not stop the auth
	// loop's goroutines; the context cancel does).
	exitCancels []context.CancelFunc

	// observability snapshot for Status(), guarded by mu: the bootstrap
	// phase, when the first session went live, and the broker-roster
	// refresh bookkeeping (refreshErr is soft — a failed poll keeps the
	// previous roster).
	phase      string    // "starting", "connecting", "running"
	readyAt    time.Time // when the first live session appeared
	refreshAt  time.Time // last successful broker roster fetch
	refreshErr error     // last roster fetch failure
	closed     bool      // Close was called

	// watch signals the engine that the outbound set changed (ready flip).
	watchCh chan struct{}

	// stop cancels the client; stopped is closed when the run goroutine exits.
	stop    context.CancelFunc
	stopped chan struct{}
	// runCtx is the provider's own background lifetime (canceled by stop). Per-exit
	// clients derive their lifetime from it, NOT from the dial request context: a
	// request ctx is canceled when its inbound handler returns, which would kill a
	// cached per-exit client's auth loop and sessions after the first request and
	// leave a dead-but-cached client that is never restarted. Set once at
	// construction before the provider is registered, so reads need no lock.
	runCtx context.Context

	// pinnedDialer starts per-exit clients lazily; swapped for a fake in tests.
	pinnedDialer func(ctx context.Context, hostname string) (clientConn, error)

	// brokerDialer carries the client's control plane — the broker transport
	// (roster/net-status fetches, auth RPCs, exit-route requests): the
	// injected upstream route's dialer when the spec's upstream_proxy names
	// a goose route, else the engine's layer-3/4 stack dialer. stackDialer
	// carries the data path — the exit route tree's raw TCP, including every
	// pinned per-exit client — and is always the engine stack dialer (or nil
	// for the system dialer), never the provider upstream. Both are stored at
	// factory time because per-exit clients are started later, from the dial
	// path, where the config map is no longer reachable.
	brokerDialer func(ctx context.Context, network, address string) (net.Conn, error)
	stackDialer  func(ctx context.Context, network, address string) (net.Conn, error)
	// viaRoute records that brokerDialer came from an injected engine route
	// (the spec's upstream_proxy names an outbound:/pool:/chain:); surfaced
	// through Status details as "engine_route".
	viaRoute bool
}

// The provider reports live self-assessed state to the engine's status API.
var _ pub.StatusReporter = (*Provider)(nil)

// setPhase records the bootstrap phase shown by Status().
func (p *Provider) setPhase(phase string) {
	p.mu.Lock()
	p.phase = phase
	p.mu.Unlock()
}

// exitClientState tracks one lazily-booted per-exit client: the client, a
// cached start failure (retried after exitStartRetry), and the time of the
// last dial through it.
type exitClientState struct {
	mu       sync.Mutex
	client   clientConn
	startErr error
	startAt  time.Time
	lastUse  time.Time
}

// providerConfig is the deserialized provider config.
type providerConfig struct {
	ConfigPath     string          `json:"config_path"`
	OutboundID     string          `json:"outbound_id"`
	ExitConstraint json.RawMessage `json:"exit_constraint"`
	Credentials    json.RawMessage `json:"credentials"`
	Secret         string          `json:"secret"`
	Username       string          `json:"username"`
	Password       string          `json:"password"`
	Cache          string          `json:"cache"`
	Broker         json.RawMessage `json:"broker"`
	BrokerKeys     json.RawMessage `json:"broker_keys"`

	// EmbeddedExit enables standalone mode. json.RawMessage so the value can
	// be true or an options object; parsed by embeddedExitOptions.
	EmbeddedExit json.RawMessage `json:"embedded_exit"`
}

// embeddedExitOptions is the parsed "embedded_exit" object form.
type embeddedExitOptions struct {
	Listen        string `json:"listen"`
	AllowLoopback bool   `json:"allow_loopback"`
	SeedHex       string `json:"seed_hex"`
}

// parseEmbeddedExit parses the "embedded_exit" config value: absent/false
// means disabled, true means defaults, and an object carries the knobs.
func parseEmbeddedExit(raw json.RawMessage) (embeddedExitOptions, bool, error) {
	if len(raw) == 0 {
		return embeddedExitOptions{}, false, nil
	}
	var enabled bool
	if err := json.Unmarshal(raw, &enabled); err == nil {
		return embeddedExitOptions{}, enabled, nil
	}
	var opts embeddedExitOptions
	if err := json.Unmarshal(raw, &opts); err != nil {
		return embeddedExitOptions{}, false, fmt.Errorf("geph provider: embedded_exit must be true or an object: %w", err)
	}
	return opts, true, nil
}

// exitlibOptions converts the plugin knob into exitlib.Options, consuming
// SeedHex when given.
func (o embeddedExitOptions) exitlibOptions() (exitlib.Options, error) {
	opts := exitlib.Options{
		C2EListen:     o.Listen,
		AllowLoopback: o.AllowLoopback,
	}
	if o.SeedHex != "" {
		seed, err := hex.DecodeString(o.SeedHex)
		if err != nil {
			return exitlib.Options{}, fmt.Errorf("geph provider: embedded_exit seed_hex: %w", err)
		}
		if len(seed) != 32 {
			return exitlib.Options{}, fmt.Errorf("geph provider: embedded_exit seed_hex must be 64 hex chars (32 bytes), got %d bytes", len(seed))
		}
		copy(opts.Seed[:], seed)
	}
	return opts, nil
}

// engineDialers resolves the two engine-injected dialers by role. brokerDialer
// carries the client's control plane (the broker transport): the upstream
// route dialer when the provider spec's upstream_proxy names a goose route
// (outbound:/pool:/chain: — the engine injects it under pub.UpstreamDialerKey),
// else the engine's layer-3/4 stack dialer, else nil (the system dialer, e.g.
// unit tests). stackDialer carries the data path (the exit route tree's raw
// TCP): the engine's stack dialer only — the provider upstream must never
// carry the outbounds' own server dials — else nil. viaRoute reports the route
// case.
func engineDialers(cfg map[string]any) (brokerDialer, stackDialer func(ctx context.Context, network, address string) (net.Conn, error), viaRoute bool) {
	if sd := pub.AsStackDialer(cfg); sd != nil {
		stackDialer = sd.Dial
	}
	if ud := pub.AsUpstreamDialer(cfg); ud != nil {
		return ud.DialUpstream, stackDialer, true
	}
	return stackDialer, stackDialer, false
}

// NewProvider is the ProviderFactory registered as "geph". It parses the
// config and starts the geph5 client bootstrap in the background; Outbounds
// advertises the broker-known exit roster as soon as it is retrieved and adds
// the general "geph" outbound once the client has a live session.
func NewProvider(cfg map[string]any) (pub.Provider, error) {
	pc, err := parseConfig(cfg)
	if err != nil {
		return nil, err
	}
	if pc.OutboundID == "" {
		pc.OutboundID = "geph"
	}

	// Route the client's own TCP through the engine, split by role: broker
	// fetches (the control plane) ride the injected upstream route when the
	// spec's upstream_proxy names a goose outbound/pool/chain, else the
	// engine's layer-3/4 stack (system kernel or gvisor netstack); exit dials
	// (the data path) ride the engine stack only, never the provider
	// upstream. When neither is injected (e.g. unit tests) the client falls
	// back to the system dialer.
	brokerDialer, stackDialer, viaRoute := engineDialers(cfg)

	p := &Provider{
		cfg:          pc,
		watchCh:      make(chan struct{}, 1),
		stopped:      make(chan struct{}),
		brokerDialer: brokerDialer,
		stackDialer:  stackDialer,
		viaRoute:     viaRoute,
	}
	p.pinnedDialer = p.startExitClient
	ctx, cancel := context.WithCancel(context.Background())
	p.stop = cancel
	p.runCtx = ctx
	go func() {
		defer close(p.stopped)
		p.run(ctx)
	}()
	registerLiveProvider(p)
	return p, nil
}

// dialConn is the in-memory dial entry for the "geph" outbound protocol: it
// opens a connection to remote through the live session manager — the same
// path the SOCKS5 listener hands CONNECTs to, called directly.
func (p *Provider) dialConn(ctx context.Context, remote string) (net.Conn, error) {
	p.mu.Lock()
	client := p.client
	ready := p.ready
	p.mu.Unlock()
	if client == nil || !ready {
		return nil, fmt.Errorf("geph provider: no live session (client not running or still establishing)")
	}
	return client.OpenConn(ctx, remote)
}

// exitStartRetry bounds how long a failed per-exit client start is cached
// before a later dial retries it (mirrors psiphon's pinned-controller retry).
const exitStartRetry = 30 * time.Second

// dialExit is dialConn with the client pinned to one broker-known exit
// (hostname), the per-server dial form behind each per-exit outbound. The
// pinned client is started lazily on first dial and shared by every dial to
// that exit (a full session stack is too heavy to boot per connection): the
// state lock serializes the start, a fresh client's first dial waits for its
// first live session, and later dials ride the established one. A failed
// start is retried after exitStartRetry; idle clients are reaped on the next
// Outbounds poll.
func (p *Provider) dialExit(ctx context.Context, hostname, remote string) (net.Conn, error) {
	client, err := p.getOrStartExitClient(ctx, hostname)
	if err != nil {
		return nil, err
	}
	// Wait for the pinned client's first session before handing the dial
	// over — an OpenConn with no session would fail anyway, but this bounds
	// the wait and surfaces "still establishing" instead of a tunnel error.
	wctx, cancel := context.WithTimeout(ctx, exitWaitSession)
	defer cancel()
	if err := p.awaitExitSession(wctx, client); err != nil {
		return nil, fmt.Errorf("geph provider: exit %s: %w", hostname, err)
	}
	return client.OpenConn(ctx, remote)
}

// chainClient is the optional chaining capability of a per-exit client: dialing
// a target over an existing upstream transport conn (the goose ChainDialer
// path). *clientlib.Client implements it; the test fakes (which only model
// OpenConn) do not, so the provider type-asserts rather than widening clientConn.
type chainClient interface {
	DialThrough(ctx context.Context, via net.Conn, remote string) (net.Conn, error)
}

// dialExitThrough is the chained form of dialExit: the previous hop has already
// tunneled to the pinned exit's c2e listener (via), and geph establishes a
// one-off session over that tunnel instead of dialing the exit from the local
// network. It reuses the same lazily-started per-exit client as dialExit (for
// its auth manager and direct constraint) but does NOT wait for a background
// session — DialThrough establishes its own session synchronously over via.
//
// via ownership follows the router's ChainDialer contract: on success the
// returned conn owns via; on error the router closes via (and DialThrough closes
// it too once handed off — a benign double close).
func (p *Provider) dialExitThrough(ctx context.Context, hostname, remote string, via net.Conn) (net.Conn, error) {
	client, err := p.getOrStartExitClient(ctx, hostname)
	if err != nil {
		return nil, err
	}
	cc, ok := client.(chainClient)
	if !ok {
		return nil, fmt.Errorf("geph provider: exit %s client does not support chaining", hostname)
	}
	return cc.DialThrough(ctx, via, remote)
}

// getOrStartExitClient returns the lazily-started per-exit client for hostname,
// booting it on first use (shared by every dial to that exit — a full session
// stack is too heavy to boot per connection). The state lock serializes the
// start so concurrent dials cannot race a second client into existence; a failed
// start is cached and retried after exitStartRetry. Both dialExit (background
// session) and dialExitThrough (one-off chained session) use it.
func (p *Provider) getOrStartExitClient(ctx context.Context, hostname string) (clientConn, error) {
	for {
		p.mu.Lock()
		st, ok := p.exitClients[hostname]
		if !ok {
			st = &exitClientState{}
			if p.exitClients == nil {
				p.exitClients = map[string]*exitClientState{}
			}
			p.exitClients[hostname] = st
		}
		p.mu.Unlock()

		st.mu.Lock()
		// Re-validate this state is still the mapped one: the idle reaper may have
		// removed it (and closed/nil'd its client) between the map lookup above and
		// this lock. If so, drop it and loop to get-or-create a fresh state rather
		// than starting a client into an orphaned state no future dial will find.
		// st.mu -> p.mu, the same order startExitClient and the reaper use, so this
		// adds no lock inversion.
		p.mu.Lock()
		cur, mapped := p.exitClients[hostname]
		p.mu.Unlock()
		if !mapped || cur != st {
			st.mu.Unlock()
			continue
		}
		// Re-gate tier on EVERY dial, not only at boot. A per-exit client booted
		// during warmup (account tier still unknown) for an exit this account
		// cannot use would otherwise be cached and returned forever, latching the
		// warmup skip into opaque auth-EOF failures even after the tier becomes
		// known. Gating here — before the boot/cache path and before lastUse is
		// refreshed — surfaces the actionable tier error and lets a doomed client
		// idle-reap rather than be kept alive by rejected traffic. checkExitTier
		// and exitLevels lock p.mu under st.mu (st.mu -> p.mu), the order used
		// throughout this path, so this adds no lock inversion.
		if err := p.checkExitTier(hostname, p.exitLevels(hostname)); err != nil {
			st.mu.Unlock()
			return nil, err
		}
		if st.client == nil && (st.startErr == nil || time.Since(st.startAt) > exitStartRetry) {
			// Start under the state lock so a concurrent dial to the same exit
			// cannot race a second client into existence.
			client, err := p.pinnedDialer(ctx, hostname)
			st.startAt = time.Now()
			if err != nil {
				st.startErr = err
				st.mu.Unlock()
				return nil, fmt.Errorf("geph provider: start client for exit %s: %w", hostname, err)
			}
			st.startErr = nil
			st.client = client
			log.Printf("geph provider: per-exit client for %s started", hostname)
		}
		st.lastUse = time.Now()
		client := st.client
		startErr := st.startErr
		st.mu.Unlock()

		if client == nil {
			// The cached failure is retried by a later dial (see the window
			// above); this dial only reports it.
			return nil, fmt.Errorf("geph provider: exit %s unavailable (recent start failed, retrying later): %w", hostname, startErr)
		}
		return client, nil
	}
}

// awaitExitSession polls until the client reports a live session or ctx ends.
func (p *Provider) awaitExitSession(ctx context.Context, client clientConn) error {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		if client.SessionCount() > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no live session: %w", ctx.Err())
		case <-tick.C:
		}
	}
}

// startExitClient boots a full embedded geph5 client pinned to one roster exit
// via a client-side "direct" (c2e/pubkey) constraint. It is the production
// pinnedDialer; tests swap it. The client's lifetime is the provider's background
// context (runCtx), canceled by Close — NOT the dial request ctx, which the
// inbound cancels when its handler returns and would otherwise kill the cached
// client's auth loop and sessions after the first request. Like the primary
// client, its broker fetches ride brokerDialer (the provider upstream when
// injected) and its exit dials ride stackDialer.
func (p *Provider) startExitClient(_ context.Context, hostname string) (clientConn, error) {
	clientCfg, err := buildClientConfig(p.cfg)
	if err != nil {
		return nil, err
	}
	// Pin the specific exit with a client-side "direct" constraint
	// ("c2e/pubkeyhex"). The broker resolves neither a hostname constraint
	// carrying the roster's pubkey-hex key ("no exits match the constraints")
	// nor a direct constraint sent over RPC ("direct constraints must not be
	// sent to the broker"); GetDialer handles "direct" locally (getDialerDirect),
	// dialing the exit's c2e through the stack dialer — which, in a chain, rides
	// the upstream tunnel. Look up the c2e/pubkey from the current roster.
	p.mu.Lock()
	var c2e, pubkey string
	var levels []string
	for _, e := range p.exits {
		if e.Hostname == hostname {
			c2e, pubkey = e.C2EListen, e.PubkeyHex
			levels = e.AllowedLevels
			break
		}
	}
	p.mu.Unlock()
	if c2e == "" || pubkey == "" {
		return nil, fmt.Errorf("geph provider: exit %s not in current roster (no c2e/pubkey to pin)", hostname)
	}
	// Fail fast with an actionable reason when THIS provider's account cannot use
	// the exit, rather than booting a client whose auth handshake the exit will
	// silently close (a Plus-only exit rejects a Free credential mid-hello). A
	// chain pinned to such an exit gets this clear error instead of an opaque
	// "read exit hello: EOF".
	if err := p.checkExitTier(hostname, levels); err != nil {
		return nil, err
	}
	clientCfg.ExitConstraint = brokerproto.ExitConstraint{Kind: "direct", Direct: c2e + "/" + pubkey}
	// Lifetime = the provider's background context, not the dial request ctx (see
	// the method comment): the cached client must outlive the first request.
	// Providers constructed directly in tests carry no runCtx; fall back to
	// Background there (the test closes the client explicitly). NewProvider always
	// sets runCtx, so production clients are canceled with the provider.
	parent := p.runCtx
	if parent == nil {
		parent = context.Background()
	}
	cancelCtx, cancel := context.WithCancel(parent)
	p.mu.Lock()
	p.exitCancels = append(p.exitCancels, cancel)
	p.mu.Unlock()
	client, err := clientlib.Start(cancelCtx, clientlib.Options{
		NoListener:   true,
		StackDialer:  p.stackDialer,
		BrokerDialer: p.brokerDialer,
		Config:       clientCfg,
	})
	if err != nil {
		cancel()
		return nil, err
	}
	return client, nil
}

// reapExitClients stops and drops pinned clients that have gone exitIdleClose
// without a dial. Called from Outbounds — every engine poll — so there is no
// dedicated reaper goroutine; each reaped client's Close stops its session
// manager, and its exitCancels entry fires with the provider.
func (p *Provider) reapExitClients() {
	// Snapshot the states under p.mu, then release it. The reaper locks each
	// st.mu BEFORE p.mu (st.mu -> p.mu) — the SAME order the start path uses
	// (getOrStartExitClient holds st.mu across startExitClient, which locks p.mu
	// for the roster lookup and exitCancels append). The previous version held
	// p.mu while locking st.mu (p.mu -> st.mu), closing an ABBA cycle with the
	// start path that could permanently wedge the provider (every later p.mu
	// user — Status, Outbounds, dialConn, even Close — would block).
	p.mu.Lock()
	type candidate struct {
		hostname string
		st       *exitClientState
	}
	cands := make([]candidate, 0, len(p.exitClients))
	for hostname, st := range p.exitClients {
		cands = append(cands, candidate{hostname, st})
	}
	p.mu.Unlock()

	var reaped []clientConn
	for _, c := range cands {
		c.st.mu.Lock()
		idle := !c.st.lastUse.IsZero() && time.Since(c.st.lastUse) > exitIdleClose
		client := c.st.client
		if idle && client != nil {
			p.mu.Lock()
			// Re-check the map still holds this exact state: a concurrent Close or
			// restart may have replaced/removed it since the snapshot.
			if cur, ok := p.exitClients[c.hostname]; ok && cur == c.st {
				delete(p.exitClients, c.hostname)
				c.st.client = nil
				reaped = append(reaped, client)
			}
			p.mu.Unlock()
		}
		c.st.mu.Unlock()
	}
	for _, client := range reaped {
		client.Close()
		log.Printf("geph provider: reaped idle per-exit client")
	}
}

// parseConfig marshals the plugin config map into providerConfig. The
// engine-injected dialer values (func/interface under the reserved
// "_dialer"/"_upstream_dialer" keys) are dropped first: they are consumed
// via AsStackDialer/AsUpstreamDialer in NewProvider, and json.Marshal would
// choke on them.
func parseConfig(cfg map[string]any) (providerConfig, error) {
	cfg = maps.Clone(cfg)
	delete(cfg, pub.StackDialerKey)
	delete(cfg, pub.UpstreamDialerKey)
	if cfg == nil {
		return providerConfig{}, nil
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return providerConfig{}, fmt.Errorf("geph provider: marshal config: %w", err)
	}
	var pc providerConfig
	if err := json.Unmarshal(raw, &pc); err != nil {
		return providerConfig{}, fmt.Errorf("geph provider: parse config: %w", err)
	}
	return pc, nil
}

// buildClientConfig assembles the geph5 client config for the provider: a YAML
// file (config_path) as the base, with the inline provider knobs applied over
// it. It returns an error when neither source yields an exit constraint.
func buildClientConfig(pc providerConfig) (*config.Config, error) {
	var cfg *config.Config
	if pc.ConfigPath != "" {
		loaded, err := config.LoadYAML(pc.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("geph provider: load config_path %s: %w", pc.ConfigPath, err)
		}
		cfg = loaded
	} else {
		cfg = &config.Config{}
	}

	// Overlay the inline knobs.
	if pc.ExitConstraint != nil {
		// exit_constraint may be given inline in its native enum shape
		// ("auto", {"direct": "..."}, {"hostname": "..."}, ...) — re-wrap it
		// so config.Config's ExitConstraint.UnmarshalJSON sees the value.
		wrapped, err := json.Marshal(struct {
			ExitConstraint json.RawMessage `json:"exit_constraint"`
		}{ExitConstraint: pc.ExitConstraint})
		if err != nil {
			return nil, fmt.Errorf("geph provider: wrap exit constraint: %w", err)
		}
		if err := json.Unmarshal(wrapped, cfg); err != nil {
			return nil, fmt.Errorf("geph provider: parse exit constraint: %w", err)
		}
	}
	if pc.Credentials != nil {
		wrapped, err := json.Marshal(struct {
			Credentials json.RawMessage `json:"credentials"`
		}{Credentials: pc.Credentials})
		if err != nil {
			return nil, fmt.Errorf("geph provider: wrap credentials: %w", err)
		}
		if err := json.Unmarshal(wrapped, cfg); err != nil {
			return nil, fmt.Errorf("geph provider: parse credentials: %w", err)
		}
	} else if pc.Secret != "" {
		// Shorthand: "secret": "..." is the {secret: ...} credential.
		if err := json.Unmarshal([]byte(`{"credentials":{"secret":`+quoteJSONString(pc.Secret)+`}}`), cfg); err != nil {
			return nil, fmt.Errorf("geph provider: parse secret credential: %w", err)
		}
	} else if pc.Username != "" || pc.Password != "" {
		if err := json.Unmarshal([]byte(`{"credentials":{"legacy_username_password":{"username":`+quoteJSONString(pc.Username)+`,"password":`+quoteJSONString(pc.Password)+`}}}`), cfg); err != nil {
			return nil, fmt.Errorf("geph provider: parse username/password credential: %w", err)
		}
	}
	if pc.Broker != nil {
		var wrap struct {
			Broker json.RawMessage `json:"broker"`
		}
		// The YAML broker source is externally tagged; the plugin config may
		// pass a bare string (direct) or the tagged object. Re-wrap it.
		brokerJSON, err := normalizeBrokerJSON(pc.Broker)
		if err != nil {
			return nil, err
		}
		wrap.Broker = brokerJSON
		wrapped, err := json.Marshal(wrap)
		if err != nil {
			return nil, fmt.Errorf("geph provider: wrap broker: %w", err)
		}
		if err := json.Unmarshal(wrapped, cfg); err != nil {
			return nil, fmt.Errorf("geph provider: parse broker: %w", err)
		}
	}
	if pc.BrokerKeys != nil {
		wrapped, err := json.Marshal(struct {
			BrokerKeys json.RawMessage `json:"broker_keys"`
		}{BrokerKeys: pc.BrokerKeys})
		if err != nil {
			return nil, fmt.Errorf("geph provider: wrap broker keys: %w", err)
		}
		if err := json.Unmarshal(wrapped, cfg); err != nil {
			return nil, fmt.Errorf("geph provider: parse broker keys: %w", err)
		}
	}
	if pc.Cache != "" {
		cache := pc.Cache
		cfg.Cache = &cache
	}

	// Zero-config production case: with no config_path, embedded_exit, or
	// inline exit_constraint/broker, fill the embedded production network
	// parameters (auto constraint, direct broker, keys) so the provider
	// retrieves the live exit roster out of the box, like psiphon's embedded
	// config. Specific modes (direct pin, custom broker, YAML, standalone)
	// are left untouched.
	if zeroConfigProduction(pc) {
		applyProductionDefaults(cfg)
	}
	return cfg, nil
}

// normalizeBrokerJSON converts a plugin-provided broker value (bare URL
// string or {"direct": "..."} / {"fronted": {...}} object) into host-raw JSON
// for config.Config.Broker's externally-tagged unmarshaler.
func normalizeBrokerJSON(raw json.RawMessage) (json.RawMessage, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		// Bare string: the "direct" source.
		out, err := json.Marshal(map[string]string{"direct": s})
		if err != nil {
			return nil, fmt.Errorf("geph provider: marshal direct broker: %w", err)
		}
		return out, nil
	}
	// Already an object; pass through (config.BrokerSource.UnmarshalJSON
	// handles the tagged variants via the json path).
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("geph provider: broker must be a URL string or a tagged object: %w", err)
	}
	return raw, nil
}

// quoteJSONString marshals s to a quoted JSON string literal.
func quoteJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// run starts the embedded geph5 client and waits for its first live session,
// updating the provider's ready state as things change. It blocks until ctx
// is canceled; clientlib owns the client's internal retry semantics, so
// unlike the tor provider there is no backoff loop here — the session manager
// already retries tunnel establishment forever.
func (p *Provider) run(ctx context.Context) {
	p.setPhase("starting")
	clientCfg, err := buildClientConfig(p.cfg)
	if err != nil {
		p.setTerminal(err)
		return
	}

	// Standalone mode: boot the exit server in-process and pin the client at
	// it, overriding whatever exit constraint the config carried (a log note,
	// not an error — the point of embedded_exit is to not need one).
	if raw := p.cfg.EmbeddedExit; len(raw) > 0 {
		opts, enabled, err := parseEmbeddedExit(raw)
		if err != nil {
			p.setTerminal(err)
			return
		}
		if enabled {
			exitOpts, err := opts.exitlibOptions()
			if err != nil {
				p.setTerminal(err)
				return
			}
			exit, err := exitlib.Start(ctx, exitOpts)
			if err != nil {
				p.setTerminal(fmt.Errorf("geph provider: start embedded exit: %w", err))
				return
			}
			p.mu.Lock()
			p.exit = exit
			p.mu.Unlock()
			clientCfg.ExitConstraint = brokerproto.ExitConstraint{
				Kind:   "direct",
				Direct: exit.C2EAddr() + "/" + exit.PubkeyHex(),
			}
			log.Printf("geph provider: embedded exit serving c2e at %s (pubkey %s); exit constraint overridden", exit.C2EAddr(), exit.PubkeyHex())
		}
	}

	// NoListener: nothing binds — the "geph" outbound dials the session
	// manager in process via Client.OpenConn. The engine dialers split by
	// role: brokerDialer (injected upstream route, else layer-3/4 stack)
	// carries the broker fetches; stackDialer carries the exit route tree.
	client, err := clientlib.Start(ctx, clientlib.Options{
		NoListener:   true,
		StackDialer:  p.stackDialer,
		BrokerDialer: p.brokerDialer,
		Config:       clientCfg,
	})
	if err != nil {
		p.setTerminal(err)
		return
	}
	p.mu.Lock()
	p.client = client
	p.phase = "connecting"
	p.mu.Unlock()

	// The broker exit roster is the provider's server-list source — the geph
	// analogue of psiphon's datastore. Refresh it independently of session
	// readiness (in this goroutine, blocking until ctx ends) so the real exit
	// list is retrieved and advertised zero-config, even before — or without —
	// a live session: a credential-less client still discovers servers, while
	// tunneling awaits an operator-supplied secret. Each refresh re-signals
	// Watch so the engine repolls Outbounds; idle per-exit clients are reaped
	// on the same ticker.
	//
	// The ready flip runs alongside: when the first live session appears the
	// general "geph" outbound is advertised too. There is no terminal timeout
	// — the session manager retries tunnel establishment forever (mirroring
	// tor/psiphon), so a credential-less zero-config client keeps the roster
	// advertised in the "connecting" state rather than erroring out.
	go p.awaitSession(ctx, client)
	p.refreshLoop(ctx, client)
}

// exitListInterval is how often the provider re-fetches the broker's exit
// roster. Slow on purpose: the roster changes rarely and each poll is a
// broker RPC through possibly-censored wires.
const exitListInterval = 10 * time.Minute

// refreshLoop blocks until ctx is canceled, periodically refreshing the
// broker-known exit roster and reaping idle per-exit clients. The FIRST
// refresh happens immediately after the client starts — independent of session
// readiness — so the exit list fills the web UI zero-config without waiting for
// a live session (or a full interval).
func (p *Provider) refreshLoop(ctx context.Context, client *clientlib.Client) {
	p.refreshExitsOnce(ctx, client)
	t := time.NewTicker(exitListInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.reapExitClients()
			p.refreshExitsOnce(ctx, client)
		}
	}
}

// refreshExitsOnce fetches the broker's net status and stores the exit
// roster on the provider, signaling Watch when the roster changed. It fails
// soft: a broker hiccup keeps the previous list (an empty roster simply
// means no per-exit outbounds, the general outbound still works).
func (p *Provider) refreshExitsOnce(ctx context.Context, client *clientlib.Client) {
	if client == nil {
		return
	}
	broker, err := client.BrokerClient()
	if err != nil {
		// No broker (e.g. standalone/direct mode): there is no roster to
		// list. Only the general outbound is emitted, which is the
		// pre-existing behavior — connection pinned, nothing to do.
		return
	}
	signed, err := broker.GetNetStatus(ctx)
	if err != nil || signed == nil {
		log.Printf("geph provider: net status fetch failed: %v", err)
		p.mu.Lock()
		p.refreshErr = fmt.Errorf("net status fetch failed: %w", err)
		p.mu.Unlock()
		return
	}
	var status brokerproto.NetStatus
	// Early exits (direct constraint) may serve net_status unsigned.
	if err := json.Unmarshal([]byte(signed.InnerLiteral), &status); err != nil {
		log.Printf("geph provider: parse net status: %v", err)
		p.mu.Lock()
		p.refreshErr = fmt.Errorf("parse net status: %w", err)
		p.mu.Unlock()
		return
	}
	exits := make([]exitInfo, 0, len(status.Exits))
	for hostname, entry := range status.Exits {
		levels := make([]string, len(entry.Metadata.AllowedLevels))
		for i, l := range entry.Metadata.AllowedLevels {
			levels[i] = string(l)
		}
		exits = append(exits, exitInfo{
			Hostname:      hostname,
			PubkeyHex:     entry.PubkeyHex(),
			C2EListen:     entry.Exit.C2EListen,
			Country:       entry.Exit.Country,
			City:          entry.Exit.City,
			AllowedLevels: levels,
		})
	}
	sort.Slice(exits, func(i, j int) bool { return exits[i].Hostname < exits[j].Hostname })
	p.mu.Lock()
	changed := !exitsEqual(p.exits, exits)
	p.exits = exits
	p.refreshAt = time.Now()
	p.refreshErr = nil
	p.mu.Unlock()
	if changed {
		p.signalWatch()
	}
}

// exitsEqual reports whether two rosters list the same exits (identity =
// hostname; descriptors may refresh underneath).
func exitsEqual(a, b []exitInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Hostname != b[i].Hostname {
			return false
		}
	}
	return true
}

// awaitSession polls the session manager until at least one session is live
// (so the general outbound can carry data), flips ready, and returns. It also
// returns when ctx is canceled. There is no deadline: the session manager
// retries forever, and a credential-less zero-config client simply never flips
// ready while the independently-refreshed exit roster stays advertised.
func (p *Provider) awaitSession(ctx context.Context, client clientConn) {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if client.SessionCount() > 0 {
			p.mu.Lock()
			p.ready = true
			p.phase = "running"
			p.readyAt = time.Now()
			p.mu.Unlock()
			log.Printf("geph provider: geph5 client has a live session")
			p.signalWatch()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// setTerminal records a startup error and wakes the engine for one final poll
// so Outbounds can surface it.
func (p *Provider) setTerminal(err error) {
	p.mu.Lock()
	p.startErr = err
	p.mu.Unlock()
	p.signalWatch()
}

// Name returns the provider plugin name.
func (p *Provider) Name() string { return "geph" }

// Watch returns the change signal channel.
func (p *Provider) Watch() <-chan struct{} { return p.watchCh }

// Outbounds returns the current outbound set: one outbound per broker-known
// exit — the geph analogue of the psiphon/tor per-server lists, sourced from
// the broker's net status — advertised as soon as the roster is retrieved,
// independent of session readiness, so the engine's web UI can show and pin the
// real exit list zero-config. The general "geph" outbound (riding the primary
// client's live session) is added once a session is live. Per-exit outbounds
// are named <id>-<hostname>-<host:port>: the exit's c2e address is appended so
// the id itself carries the proxy server it pins (the general outbound keeps
// its plain id — it rides a live session, not one server). The dial is pinned
// to that exit's hostname constraint via the "exit_hostname" config key. A
// terminal startup failure returns the error so the engine logs it (the
// existing pool, if any, is kept).
func (p *Provider) Outbounds(_ context.Context) ([]pub.OutboundConfig, error) {
	// Rendezvous point for the idle reaper: every engine poll (~2 min) walks
	// the pinned clients and stops the ones no dial touched for
	// exitIdleClose.
	p.reapExitClients()

	p.mu.Lock()
	ready := p.ready
	err := p.startErr
	id := p.cfg.OutboundID
	exits := append([]exitInfo(nil), p.exits...)
	p.mu.Unlock()
	// Deterministic order regardless of how the roster was stored: the web
	// Outbounds list and pool diffs stay stable across polls.
	sort.Slice(exits, func(i, j int) bool { return exits[i].Hostname < exits[j].Hostname })
	if err != nil {
		return nil, err
	}

	// The per-exit roster is advertised as soon as it is retrieved, independent
	// of session readiness — like psiphon emitting its datastore servers without
	// waiting for the main tunnel. The general "geph" outbound rides the primary
	// client's live session, so it is added only once ready.
	var out []pub.OutboundConfig
	if ready {
		out = append(out, pub.OutboundConfig{
			ID:       id,
			Protocol: "geph",
			Config: map[string]any{
				"id":     id,
				"tunnel": id,
			},
		})
	}
	// Advertise every discovered exit, regardless of the account's tier. The
	// roster is a stable discovery surface: removing an exit here would make the
	// engine delete its outbound id, and a chain pinned to that id would silently
	// drop the hop (the router skips unknown references) and exit via the upstream
	// proxy instead — a silent exit-path override in a circumvention tool. Tier
	// eligibility is enforced per-dial by getOrStartExitClient, which fails loudly
	// with an actionable error when the account cannot use the exit.
	//
	// Each per-exit outbound is marked pin_only (the goose reserved config key):
	// it exists to be PINNED by an explicit chain/pool reference, not auto-selected.
	// The engine excludes pin_only outbounds from provider-managed pool membership
	// and the implicit all-outbounds fallback, so a Free account's default
	// pool/fallback never round-robins onto a Plus-only exit it cannot use (which
	// would fail the majority of requests with no retry or self-healing). The
	// aggregate "geph" outbound above is the auto-selectable route: it rides the
	// primary client's session pool, which only holds live (tier-usable) sessions.
	// allowed_levels rides in Config so the UI can show which exits the current
	// account may tunnel through.
	seen := map[string]int{}
	for _, e := range exits {
		// Append the exit's c2e address so the id carries the proxy server's
		// host:port literally (the subscription/mihomo id convention). The
		// hostname stays the dial pin; exits without a known address keep the
		// plain hostname id.
		exitID := id + "-" + e.Hostname
		if e.C2EListen != "" {
			exitID += "-" + e.C2EListen
		}
		// Hostnames are unique broker-map keys, but a hostname containing a
		// dash could still concatenate into another exit's id+address; the
		// subscription-style suffix keeps every id unique regardless.
		seen[exitID]++
		if n := seen[exitID]; n > 1 {
			exitID = fmt.Sprintf("%s-%d", exitID, n)
		}
		out = append(out, pub.OutboundConfig{
			ID:       exitID,
			Protocol: "geph",
			Config: map[string]any{
				"id":             exitID,
				"tunnel":         id,
				"exit_hostname":  e.Hostname,
				"address":        e.C2EListen,
				"country":        e.Country,
				"city":           e.City,
				"allowed_levels": e.AllowedLevels,
				"pin_only":       true,
			},
		})
	}
	return out, nil
}

// Status implements pub.StatusReporter: a cheap in-memory snapshot of the
// provider's own view — bootstrap phase, roster freshness, session counts —
// merged into the engine's /api/providers/status "plugin" field. All values
// are flat scalars or string slices for the UI; the provider's credential
// config (secret, username, password) is deliberately never included.
func (p *Provider) Status() pub.ProviderStatus {
	// Snapshot under mu; the session counts are read after releasing it so a
	// slow client never blocks other mu users (Close holds mu while stopping
	// the embedded exit).
	p.mu.Lock()
	startErr := p.startErr
	ready := p.ready
	readyAt := p.readyAt
	phase := p.phase
	closed := p.closed
	client := p.client
	refreshAt := p.refreshAt
	refreshErr := p.refreshErr
	exits := len(p.exits)
	stackDialer, viaRoute := p.stackDialer, p.viaRoute
	exitAddr, exitPubkey := "", ""
	if p.exit != nil {
		exitAddr = p.exit.C2EAddr()
		exitPubkey = p.exit.PubkeyHex()
	}
	pinnedStates := make([]struct {
		hostname string
		st       *exitClientState
	}, 0, len(p.exitClients))
	for host, st := range p.exitClients {
		pinnedStates = append(pinnedStates, struct {
			hostname string
			st       *exitClientState
		}{host, st})
	}
	p.mu.Unlock()

	details := map[string]any{
		"mode":            "broker",
		"exits_in_roster": exits,
		// Transport split: broker fetches ride an injected engine route
		// (spec upstream_proxy naming outbound:/pool:/chain:) when present
		// (engine_route), else the engine stack; exit dials — the outbounds'
		// data path — ride the engine layer-3/4 stack (engine_stack), never
		// the provider upstream. Both can hold at once.
		"engine_route": viaRoute,
		"engine_stack": stackDialer != nil,
	}
	if exitAddr != "" {
		details["mode"] = "embedded_exit"
		details["embedded_exit_addr"] = exitAddr
		details["embedded_exit_pubkey"] = exitPubkey
	}
	if !refreshAt.IsZero() {
		details["last_roster_refresh"] = refreshAt.UTC().Format(time.RFC3339)
	}
	if refreshErr != nil {
		details["roster_error"] = refreshErr.Error()
	}
	if client != nil {
		details["open_sessions"] = client.SessionCount()
	}
	if len(pinnedStates) > 0 {
		pinned := make([]string, 0, len(pinnedStates))
		sessions := 0
		for _, ps := range pinnedStates {
			ps.st.mu.Lock()
			c := ps.st.client
			ps.st.mu.Unlock()
			if c == nil {
				continue // start failed or reaped; retried on the next dial
			}
			pinned = append(pinned, ps.hostname)
			sessions += c.SessionCount()
		}
		sort.Strings(pinned)
		details["pinned_exits"] = pinned
		details["exit_client_sessions"] = sessions
	}

	switch {
	case closed:
		return pub.ProviderStatus{State: "stopped", Details: details}
	case startErr != nil:
		return pub.ProviderStatus{State: "error", Message: startErr.Error(), Details: details}
	case ready:
		if !readyAt.IsZero() {
			details["ready_since"] = readyAt.UTC().Format(time.RFC3339)
		}
		return pub.ProviderStatus{State: "running", Details: details}
	case client != nil:
		return pub.ProviderStatus{State: "connecting", Message: "waiting for the first live session", Details: details}
	default:
		if phase == "" {
			phase = "starting"
		}
		return pub.ProviderStatus{State: "starting", Message: phase + ": booting the embedded client", Details: details}
	}
}

// Close stops the embedded exit (standalone mode), the embedded geph5 client
// and every per-exit client, then drops the live-provider registration so
// dials for this id fail fast instead of finding a dead provider.
func (p *Provider) Close() error {
	unregisterLiveProvider(p)
	if p.stop != nil {
		p.stop()
	}
	<-p.stopped
	p.mu.Lock()
	p.ready = false
	p.closed = true
	if p.exit != nil {
		p.exit.Close()
		p.exit = nil
	}
	exitStates := p.exitClients
	p.exitClients = nil
	cancels := p.exitCancels
	p.exitCancels = nil
	if p.client != nil {
		p.client.Close()
		p.client = nil
	}
	p.mu.Unlock()
	for _, st := range exitStates {
		st.mu.Lock()
		client := st.client
		st.client = nil
		st.mu.Unlock()
		if client != nil {
			client.Close()
		}
	}
	for _, cancel := range cancels {
		cancel()
	}
	return nil
}

// signalWatch notifies the engine (non-blocking) that the outbound set may
// have changed.
func (p *Provider) signalWatch() {
	select {
	case p.watchCh <- struct{}{}:
	default:
	}
}
