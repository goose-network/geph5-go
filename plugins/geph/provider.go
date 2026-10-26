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
// The client's own TCP — broker RPCs (including domain-fronted ones) and the
// compiled route tree to the exit (sosistab3, plain TLS, meeklike, TCP
// hops) — dials through the engine's layer-3/4 stack: the engine injects its
// stack dialer under goose-plugin-api's StackDialerKey, and the plugin hands
// it to clientlib as Options.StackDialer, which threads it down to every
// BoundTcpDialer and the broker transport.
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
// factory: Outbounds returns an empty set until the client reports a live
// session, then signals Watch so the engine repolls promptly and the pool
// fills without waiting for the 2-minute fallback poll. A failed session
// (broker unreachable, exit down) is retried indefinitely inside the session
// manager's workers, so the provider itself has no terminal error path except
// an invalid config, which fails the factory immediately.
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
	"sync"
	"time"

	pub "github.com/goose-network/goose-plugin-api"

	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/clientlib"
	"github.com/geph-official/geph5-go/internal/config"
	"github.com/geph-official/geph5-go/internal/exitlib"
)

func init() {
	pub.RegisterProvider("geph", NewProvider)
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

// Provider is a goose outbound provider backed by an embedded geph5 client.
// It implements pub.Provider.
type Provider struct {
	cfg providerConfig

	// client state, guarded by mu
	mu       sync.Mutex
	ready    bool          // a live session tunnel exists
	startErr error         // terminal startup error, surfaced via Outbounds
	client   clientConn    // the embedded client (dials in process; no listener)
	exit     *exitlib.Exit // non-nil in standalone (embedded_exit) mode

	// watch signals the engine that the outbound set changed (ready flip).
	watchCh chan struct{}

	// stop cancels the client; stopped is closed when the run goroutine exits.
	stop    context.CancelFunc
	stopped chan struct{}
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

// NewProvider is the ProviderFactory registered as "geph". It parses the
// config and starts the geph5 client bootstrap in the background; Outbounds
// returns a "geph" outbound once the client has a live session, and an empty
// set before.
func NewProvider(cfg map[string]any) (pub.Provider, error) {
	pc, err := parseConfig(cfg)
	if err != nil {
		return nil, err
	}
	if pc.OutboundID == "" {
		pc.OutboundID = "geph"
	}

	// Route the client's own TCP (broker, exit route tree) through the
	// engine's layer-3/4 stack — the system kernel or gvisor netstack —
	// rather than the raw system dialer. The engine injects its dialer under
	// pub.StackDialerKey; when absent (e.g. unit tests) the client falls back
	// to the system dialer.
	var stackDialer func(ctx context.Context, network, address string) (net.Conn, error)
	if sd := pub.AsStackDialer(cfg); sd != nil {
		stackDialer = sd.Dial
	}

	p := &Provider{
		cfg:     pc,
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.stop = cancel
	go func() {
		defer close(p.stopped)
		p.run(ctx, stackDialer)
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

// parseConfig marshals the plugin config map into providerConfig. The
// engine-injected dialer values (func/interface under the reserved
// "_dialer"/"_upstream_dialer" keys) are dropped first: they are consumed
// via AsStackDialer in NewProvider, and json.Marshal would choke on them.
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
func (p *Provider) run(ctx context.Context, stackDialer func(ctx context.Context, network, address string) (net.Conn, error)) {
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
	// manager in process via Client.OpenConn. stackDialer carries the
	// engine's network stack into the client's own connections.
	client, err := clientlib.Start(ctx, clientlib.Options{
		NoListener:  true,
		StackDialer: stackDialer,
		Config:      clientCfg,
	})
	if err != nil {
		p.setTerminal(err)
		return
	}
	p.mu.Lock()
	p.client = client
	p.mu.Unlock()

	// Wait for a live session (the first tunnel through which traffic can
	// actually flow) before advertising readiness: without one, every dial
	// would fail, and advertising early would let the engine hammer a dead
	// tunnel.
	if err := p.awaitSession(ctx, client); err != nil {
		if ctx.Err() != nil {
			return
		}
		p.setTerminal(err)
		return
	}

	// Sessions may come and go; keep the outbound advertised as long as the
	// client is up, mirroring how tor's provider advertises as long as its
	// guard link is alive. SetLiveness ping failures inside a session cause
	// the session worker to rebuild tunnels automatically.
	<-ctx.Done()
}

// awaitSession polls the session manager until at least one session is live
// (so tunnels can carry data), or ctx is canceled.
func (p *Provider) awaitSession(ctx context.Context, client clientConn) error {
	deadline := time.Now().Add(5 * time.Minute)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if client.SessionCount() > 0 {
			p.mu.Lock()
			p.ready = true
			p.mu.Unlock()
			log.Printf("geph provider: geph5 client has a live session")
			p.signalWatch()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("geph provider: timed out waiting for a live session")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
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

// Outbounds returns the current outbound set: empty until the geph5 client
// has a live session, then a single "geph" outbound, which dials through this
// provider in process. A terminal startup failure returns the error so the
// engine logs it (the existing pool, if any, is kept).
func (p *Provider) Outbounds(_ context.Context) ([]pub.OutboundConfig, error) {
	p.mu.Lock()
	ready := p.ready
	err := p.startErr
	id := p.cfg.OutboundID
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !ready {
		return nil, nil
	}
	return []pub.OutboundConfig{
		{
			ID:       id,
			Protocol: "geph",
			Config: map[string]any{
				"id":     id,
				"tunnel": id,
			},
		},
	}, nil
}

// Close stops the embedded exit (standalone mode), the embedded geph5 client,
// and the run goroutine, then drops the live-provider registration so dials
// for this id fail fast instead of finding a dead provider.
func (p *Provider) Close() error {
	unregisterLiveProvider(p)
	if p.stop != nil {
		p.stop()
	}
	<-p.stopped
	p.mu.Lock()
	p.ready = false
	if p.exit != nil {
		p.exit.Close()
		p.exit = nil
	}
	if p.client != nil {
		p.client.Close()
		p.client = nil
	}
	p.mu.Unlock()
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
