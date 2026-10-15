// Package geph is the Geph outbound provider plugin for the goose proxy-pool
// engine (github.com/goose-network/goose). It embeds the geph5-go client — a
// wire-compatible Go port of the geph5 client core — as a library and exposes
// it to goose the same way the Tor provider embeds tor-go: the provider boots
// the full geph5 client (auth loop, session manager with its 6 concurrent
// tunnels, SOCKS5 listener) in the background, and once the client's listener
// is bound and at least one session to a geph5 exit is live, it emits ONE goose
// outbound of protocol "socks5" pointing at the client's loopback SOCKS5
// listener. The engine merges that outbound into the provider's managed pool,
// so any goose inbound routed through the pool forwards traffic through real
// geph5 tunnels.
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
//	  "socks_listen": "127.0.0.1:0",             // client listener (default
//	                                             // ephemeral loopback)
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
// overrides the listener and exit constraint.
package geph

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	pub "github.com/goose-network/goose-plugin-api"

	"github.com/geph-official/geph5-go/internal/clientlib"
	"github.com/geph-official/geph5-go/internal/config"
)

func init() {
	pub.RegisterProvider("geph", New)
}

// Provider is a goose outbound provider backed by an embedded geph5 client.
// It implements pub.Provider.
type Provider struct {
	cfg providerConfig

	// client state, guarded by mu
	mu        sync.Mutex
	ready     bool   // listener bound AND a live session tunnel exists
	socksAddr string // the embedded client's SOCKS5 listener address
	startErr  error  // terminal startup error, surfaced via Outbounds
	client    *clientlib.Client

	// watch signals the engine that the outbound set changed (ready flip).
	watchCh chan struct{}

	// stop cancels the client; stopped is closed when the run goroutine exits.
	stop    context.CancelFunc
	stopped chan struct{}
}

// providerConfig is the deserialized provider config.
type providerConfig struct {
	ConfigPath     string          `json:"config_path"`
	SocksListen    string          `json:"socks_listen"`
	OutboundID     string          `json:"outbound_id"`
	ExitConstraint json.RawMessage `json:"exit_constraint"`
	Credentials    json.RawMessage `json:"credentials"`
	Secret         string          `json:"secret"`
	Username       string          `json:"username"`
	Password       string          `json:"password"`
	Cache          string          `json:"cache"`
	Broker         json.RawMessage `json:"broker"`
	BrokerKeys     json.RawMessage `json:"broker_keys"`
}

// New is the ProviderFactory registered as "geph". It parses the config and
// starts the geph5 client bootstrap in the background; Outbounds returns a
// socks5 outbound once the client has a live session, and an empty set before.
func New(cfg map[string]any) (pub.Provider, error) {
	pc, err := parseConfig(cfg)
	if err != nil {
		return nil, err
	}
	if pc.OutboundID == "" {
		pc.OutboundID = "geph"
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
		p.run(ctx)
	}()
	return p, nil
}

// parseConfig marshals the plugin config map into providerConfig.
func parseConfig(cfg map[string]any) (providerConfig, error) {
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

// sessionReadyAddr returns the SOCKS5 listener address to advertise once the
// client reports a live session, else "".
func (p *Provider) sessionReadyAddr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ready {
		return ""
	}
	return p.socksAddr
}

// run starts the embedded geph5 client and waits for its first live session,
// updating the provider's ready state as things change. It blocks until ctx
// is canceled; clientlib owns the client's internal retry semantics, so
// unlike the tor provider there is no backoff loop here — the session manager
// already retries tunnel establishment forever.
func (p *Provider) run(ctx context.Context) {
	clientCfg, err := buildClientConfig(p.cfg)
	if err != nil {
		p.setTerminal(err)
		return
	}

	client, err := clientlib.Start(ctx, clientlib.Options{
		Socks5Listen: p.cfg.SocksListen,
		Config:       clientCfg,
	})
	if err != nil {
		p.setTerminal(err)
		return
	}
	p.mu.Lock()
	p.client = client
	addr := client.SocksAddr()
	p.mu.Unlock()

	// The listener is already bound; wait for a live session (the first tunnel
	// through which traffic can actually flow) before advertising readiness.
	if err := p.awaitSession(ctx, client, addr); err != nil {
		if ctx.Err() != nil {
			return
		}
		p.setTerminal(err)
		return
	}

	// Sessions may come and go; keep the outbound advertised as long as the
	// client (listener) is up, mirroring how tor's provider advertises as long
	// as its listener is up. SetLiveness ping failures inside a session cause
	// the session worker to rebuild tunnels automatically.
	<-ctx.Done()
}

// awaitSession polls the session manager until at least one session is live
// (so tunnels can carry data), or ctx is canceled. The SOCKS5 listener is
// bound, but without a live tunnel every CONNECT would fail; advertising the
// outbound before a tunnel exists would let the engine hammer a dead proxy.
func (p *Provider) awaitSession(ctx context.Context, client *clientlib.Client, socksAddr string) error {
	deadline := time.Now().Add(5 * time.Minute)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if client.SessionCount() > 0 {
			p.mu.Lock()
			p.ready = true
			p.socksAddr = socksAddr
			p.mu.Unlock()
			log.Printf("geph provider: geph5 client serving SOCKS5 at %s", socksAddr)
			p.signalWatch()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("geph provider: timed out waiting for a live session (listener at %s)", socksAddr)
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
// has a live session, then a single socks5 outbound pointing at its loopback
// SOCKS5 listener. A terminal startup failure returns the error so the engine
// logs it (the existing pool, if any, is kept).
func (p *Provider) Outbounds(_ context.Context) ([]pub.OutboundConfig, error) {
	p.mu.Lock()
	ready := p.ready
	addr := p.socksAddr
	err := p.startErr
	id := p.cfg.OutboundID
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !ready || addr == "" {
		return nil, nil
	}
	return []pub.OutboundConfig{
		{
			ID:       id,
			Protocol: "socks5",
			Config: map[string]any{
				"id":      id,
				"address": addr,
			},
		},
	}, nil
}

// Close stops the embedded geph5 client and waits for the run goroutine to
// exit. The engine's provider manager does not call Close on providers; this
// exists for embedders and tests that manage the provider lifecycle themselves.
func (p *Provider) Close() error {
	if p.stop != nil {
		p.stop()
	}
	<-p.stopped
	p.mu.Lock()
	p.ready = false
	if p.client != nil {
		p.client.Close()
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
