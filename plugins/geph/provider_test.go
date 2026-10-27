package geph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pub "github.com/goose-network/goose-plugin-api"
)

func TestParseConfig(t *testing.T) {
	pc, err := parseConfig(map[string]any{
		"config_path":     "/tmp/geph5.yaml",
		"outbound_id":     "geph-test",
		"exit_constraint": map[string]any{"direct": "127.0.0.1:9000/aa"},
		"secret":          "topsecret",
		"cache":           "/tmp/cache.db",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if pc.ConfigPath != "/tmp/geph5.yaml" {
		t.Fatalf("unexpected paths: %+v", pc)
	}
	if pc.OutboundID != "geph-test" {
		t.Fatalf("outbound id = %q", pc.OutboundID)
	}
	if pc.Secret != "topsecret" {
		t.Fatalf("secret = %q", pc.Secret)
	}
}

// TestParseConfigStripsInjectedDialers verifies the engine-injected keys
// never reach json.Marshal (they hold func/interface values, which cannot
// marshal) and that the caller's config map is left unmutated.
func TestParseConfigStripsInjectedDialers(t *testing.T) {
	fakeStack := &staticDialer{}
	cfg := map[string]any{
		"outbound_id": "geph-strip",
		// Values that would make json.Marshal fail if not removed first.
		pub.StackDialerKey:    fakeStack,
		pub.UpstreamDialerKey: fakeStack,
	}
	pc, err := parseConfig(cfg)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if pc.OutboundID != "geph-strip" {
		t.Fatalf("outbound id = %q", pc.OutboundID)
	}
	if _, still := cfg[pub.StackDialerKey]; !still {
		t.Fatal("parseConfig mutated the caller's config map")
	}
	if _, still := cfg[pub.UpstreamDialerKey]; !still {
		t.Fatal("parseConfig mutated the caller's config map")
	}
}

func TestParseConfigNil(t *testing.T) {
	pc, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig(nil): %v", err)
	}
	if pc.ConfigPath != "" || pc.OutboundID != "" || pc.Secret != "" || pc.Cache != "" {
		t.Fatalf("expected zero config, got %+v", pc)
	}
	if len(pc.ExitConstraint) != 0 || len(pc.Credentials) != 0 || len(pc.Broker) != 0 {
		t.Fatalf("expected zero config, got %+v", pc)
	}
}

// TestBuildClientConfigInline verifies that the inline knobs are applied over
// an empty base config: exit_constraint decodes into the externally-tagged
// enum, the "secret" shorthand becomes the secret credential, and cache is
// plumbed through as a pointer.
func TestBuildClientConfigInline(t *testing.T) {
	cfg, err := buildClientConfig(providerConfig{
		ExitConstraint: json.RawMessage(`{"direct":"127.0.0.1:9111/deadc0de"}`),
		Secret:         "hunter2",
		Cache:          "/tmp/x.db",
	})
	if err != nil {
		t.Fatalf("buildClientConfig: %v", err)
	}
	if cfg.ExitConstraint.Kind != "direct" || cfg.ExitConstraint.Direct != "127.0.0.1:9111/deadc0de" {
		t.Fatalf("exit constraint = %+v", cfg.ExitConstraint)
	}
	if cfg.Credentials.Kind != "secret" || cfg.Credentials.Secret != "hunter2" {
		t.Fatalf("credentials = %+v", cfg.Credentials)
	}
	if cfg.Cache == nil || *cfg.Cache != "/tmp/x.db" {
		t.Fatalf("cache = %+v", cfg.Cache)
	}
}

// TestBuildClientConfigAuto verifies the "auto" constraint (a bare string)
// parses through the same re-wrapping path.
func TestBuildClientConfigAuto(t *testing.T) {
	cfg, err := buildClientConfig(providerConfig{
		ExitConstraint: json.RawMessage(`"auto"`),
		Credentials:    json.RawMessage(`"test_dummy"`),
	})
	if err != nil {
		t.Fatalf("buildClientConfig: %v", err)
	}
	if cfg.ExitConstraint.Kind != "auto" {
		t.Fatalf("exit constraint = %+v", cfg.ExitConstraint)
	}
	if cfg.Credentials.Kind != "test_dummy" {
		t.Fatalf("credentials = %+v", cfg.Credentials)
	}
}

// TestBuildClientConfigBrokerString verifies a bare-URL broker normalizes to
// the "direct" broker source.
func TestBuildClientConfigBrokerString(t *testing.T) {
	cfg, err := buildClientConfig(providerConfig{
		ExitConstraint: json.RawMessage(`"auto"`),
		Broker:         json.RawMessage(`"https://broker.example/geph5-broker"`),
	})
	if err != nil {
		t.Fatalf("buildClientConfig: %v", err)
	}
	if cfg.Broker == nil || cfg.Broker.Kind != "direct" || cfg.Broker.Direct != "https://broker.example/geph5-broker" {
		t.Fatalf("broker = %+v", cfg.Broker)
	}
}

// TestBuildClientConfigFromYAML verifies the config_path path: a real YAML
// file on disk is loaded as the base, and inline knobs override it.
func TestBuildClientConfigFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geph5.yaml")
	yaml := []byte(`
socks5_listen: 127.0.0.1:10080
credentials: test_dummy
exit_constraint:
  hostname: example-exit.unknown
`)
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := buildClientConfig(providerConfig{
		ConfigPath:     path,
		ExitConstraint: json.RawMessage(`{"direct":"127.0.0.1:9111/deadc0de"}`),
	})
	if err != nil {
		t.Fatalf("buildClientConfig: %v", err)
	}
	// base YAML loaded
	if cfg.Socks5Listen == nil || *cfg.Socks5Listen != "127.0.0.1:10080" {
		t.Fatalf("socks5_listen = %+v", cfg.Socks5Listen)
	}
	if cfg.Credentials.Kind != "test_dummy" {
		t.Fatalf("credentials = %+v", cfg.Credentials)
	}
	// inline exit constraint replaced the YAML one
	if cfg.ExitConstraint.Kind != "direct" || cfg.ExitConstraint.Direct != "127.0.0.1:9111/deadc0de" {
		t.Fatalf("exit constraint = %+v", cfg.ExitConstraint)
	}
}

// TestProviderRegistered verifies the init() registration landed in the goose
// plugin registries: the provider under "geph", the outbound protocol under
// "geph" too.
func TestProviderRegistered(t *testing.T) {
	f, ok := pub.LookupProvider("geph")
	if !ok {
		t.Fatal(`provider "geph" not registered`)
	}
	if f == nil {
		t.Fatal("registered factory is nil")
	}
	of, ok := pub.Lookup("geph")
	if !ok || of == nil {
		t.Fatal(`outbound protocol "geph" not registered`)
	}
}

// TestOutboundsEmptyWhileStarting verifies the bootstrap pattern: a provider
// whose client is still connecting (pointed at an exit that cannot possibly
// answer) reports an empty outbound set rather than an error, so the engine's
// pool simply stays empty while the session manager retries.
func TestOutboundsEmptyWhileStarting(t *testing.T) {
	p, err := NewProvider(map[string]any{
		"exit_constraint": map[string]any{"direct": "127.0.0.1:1/deadc0de"}, // nothing listens on :1
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	defer p.(*Provider).Close()

	// Give the run goroutine a moment to start the client and begin polling.
	time.Sleep(500 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := p.Outbounds(ctx)
	if err != nil {
		t.Fatalf("Outbounds while connecting returned err=%v, want empty/nil", err)
	}
	if len(out) != 0 {
		t.Fatalf("got %d outbounds before a session is live, want 0", len(out))
	}
}

// TestOutboundsAfterReady verifies the ready flip: once a live session exists
// (simulated by setting the provider's state directly, as tor-go's test
// does), Outbounds emits one "geph" outbound with the configured id and a
// config carrying only ids (no address — dials never leave the process), and
// Watch was signaled.
func TestOutboundsAfterReady(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "geph-test"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	p.mu.Lock()
	p.ready = true
	p.mu.Unlock()
	p.signalWatch()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := p.Outbounds(ctx)
	if err != nil {
		t.Fatalf("Outbounds: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d outbounds, want 1", len(out))
	}
	if out[0].ID != "geph-test" || out[0].Protocol != "geph" {
		t.Fatalf("unexpected outbound: %+v", out[0])
	}
	if out[0].Config["id"] != "geph-test" || out[0].Config["tunnel"] != "geph-test" {
		t.Fatalf("outbound config = %v, want ids only", out[0].Config)
	}
	if _, hasAddr := out[0].Config["address"]; hasAddr {
		t.Fatalf("outbound config carries an address: %v", out[0].Config)
	}

	select {
	case <-p.Watch():
	default:
		t.Fatal("watch channel was not signaled")
	}
}

// TestOutboundFactory verifies the "geph" protocol factory: the emitted
// config builds an outbound whose ids match, and defaults apply.
func TestOutboundFactory(t *testing.T) {
	f, ok := pub.Lookup("geph")
	if !ok {
		t.Fatal(`outbound protocol "geph" not registered`)
	}
	ob, err := f(map[string]any{"id": "geph-test", "tunnel": "geph-test"})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if ob.ID() != "geph-test" || ob.Protocol() != "geph" {
		t.Fatalf("outbound = %s %s", ob.ID(), ob.Protocol())
	}

	// Defaults: bare/empty config falls back to "geph" for both ids.
	ob, err = f(map[string]any{})
	if err != nil {
		t.Fatalf("factory (defaults): %v", err)
	}
	if ob.ID() != "geph" || ob.Address() != "geph://geph" {
		t.Fatalf("default outbound = %s %s", ob.ID(), ob.Address())
	}
}

// fakeClient is a clientConn whose dials either hit a real TCP listener or
// fail immediately, counting calls.
type fakeClient struct {
	onDial func(ctx context.Context, remote string) (net.Conn, error)
	calls  atomic.Int64
}

func (f *fakeClient) OpenConn(ctx context.Context, remote string) (net.Conn, error) {
	f.calls.Add(1)
	return f.onDial(ctx, remote)
}
func (f *fakeClient) SessionCount() int { return 1 }
func (f *fakeClient) Close()            {}

// TestOutboundDialsThroughLiveProvider verifies the in-memory dial path: the
// "geph" outbound resolves the live provider from the registry at dial time
// and calls its client's OpenConn — no listener, no loopback hop.
func TestOutboundDialsThroughLiveProvider(t *testing.T) {
	// The "remote": a TCP echo server on loopback.
	remoteLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remoteLn.Close()
	remote := remoteLn.Addr().String()
	go func() {
		for {
			c, err := remoteLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				_, _ = c.Write(buf[:n])
			}(c)
		}
	}()

	fc := &fakeClient{onDial: func(ctx context.Context, r string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", r)
	}}
	p := &Provider{
		cfg:     providerConfig{OutboundID: "geph-live"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	p.mu.Lock()
	p.ready = true
	p.client = fc
	p.mu.Unlock()
	registerLiveProvider(p)
	defer unregisterLiveProvider(p)

	f, ok := pub.Lookup("geph")
	if !ok {
		t.Fatal(`outbound protocol "geph" not registered`)
	}
	ob, err := f(map[string]any{"id": "geph-live", "tunnel": "geph-live"})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := ob.DialContext(ctx, pub.NetworkTCP, remote)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
	if fc.calls.Load() != 1 {
		t.Fatalf("client dialed %d times, want 1", fc.calls.Load())
	}

	// UDP is refused: geph5 tunnels carry TCP streams.
	if _, err := ob.DialContext(ctx, pub.NetworkUDP, remote); err == nil {
		t.Fatal("UDP dial unexpectedly succeeded")
	}
}

// TestOutboundFailsWithoutProvider verifies the dial-time resolution error:
// an outbound whose provider is gone fails fast.
func TestOutboundFailsWithoutProvider(t *testing.T) {
	f, _ := pub.Lookup("geph")
	ob, err := f(map[string]any{"id": "geph-gone", "tunnel": "geph-gone"})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := ob.DialContext(ctx, pub.NetworkTCP, "127.0.0.1:80"); err == nil {
		t.Fatal("dial through a missing provider unexpectedly succeeded")
	}
}

// TestDialConnFailsWithoutClient verifies the not-ready guard on the
// provider's own dial entry.
func TestDialConnFailsWithoutClient(t *testing.T) {
	p := &Provider{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := p.dialConn(ctx, "127.0.0.1:80"); err == nil {
		t.Fatal("dialConn without a client unexpectedly succeeded")
	}
}

// TestDialConnErrorSurfaces verifies a client dial error is propagated
// wrapped, not swallowed.
func TestDialConnErrorSurfaces(t *testing.T) {
	sentinel := errors.New("no session")
	fc := &fakeClient{onDial: func(ctx context.Context, r string) (net.Conn, error) {
		return nil, sentinel
	}}
	p := &Provider{cfg: providerConfig{OutboundID: "geph-err"}}
	p.mu.Lock()
	p.ready = true
	p.client = fc
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := p.dialConn(ctx, "127.0.0.1:80")
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("dialConn err = %v, want wrapped %v", err, sentinel)
	}
}

// TestCloseStopsBootstrap verifies Close cancels the background bootstrap even
// while the client is still connecting (a session never comes up), waits for
// the run goroutine, and drops the live-provider registration.
func TestCloseStopsBootstrap(t *testing.T) {
	pAny, err := NewProvider(map[string]any{
		"outbound_id":     "geph-close",
		"exit_constraint": map[string]any{"direct": "127.0.0.1:1/deadc0de"},
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	p := pAny.(*Provider)
	if _, ok := lookupLiveProvider("geph-close"); !ok {
		t.Fatal("provider not registered before Close")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-p.stopped:
	default:
		t.Fatal("bootstrap goroutine still running after Close")
	}
	if _, ok := lookupLiveProvider("geph-close"); ok {
		t.Fatal("live-provider registration survived Close")
	}
}

// staticDialer is a StackDialer stand-in for the injection test: its Dial
// never runs in that test.
type staticDialer struct{}

func (staticDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("staticDialer: not really dialing")
}

// TestOutboundsEmitPerExit covers the per-exit list form: with a stored exit
// roster, Outbounds emits the general outbound plus one per exit, carrying
// the hostname that pins the dial's client and the display fields.
func TestOutboundsEmitPerExit(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "geph-list"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	p.mu.Lock()
	p.ready = true
	p.exits = []exitInfo{
		{Hostname: "tokyo1.example", PubkeyHex: "aa", C2EListen: "1.2.3.4:7000", Country: "JP", City: "Tokyo"},
		{Hostname: "berlin1.example", PubkeyHex: "bb", C2EListen: "5.6.7.8:7001", Country: "DE", City: "Berlin"},
	}
	p.mu.Unlock()

	out, err := p.Outbounds(context.Background())
	if err != nil {
		t.Fatalf("Outbounds: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("got %d outbounds, want 3 (general + 2 exits)", len(out))
	}
	if out[0].ID != "geph-list" {
		t.Fatalf("out[0].ID = %q, want the general outbound first", out[0].ID)
	}
	if _, pinned := out[0].Config["exit_hostname"]; pinned {
		t.Fatal("general outbound must not carry an exit pin")
	}
	for i, want := range []struct{ id, host, addr, country string }{
		{"geph-list-berlin1.example", "berlin1.example", "5.6.7.8:7001", "DE"},
		{"geph-list-tokyo1.example", "tokyo1.example", "1.2.3.4:7000", "JP"},
	} {
		got := out[1+i]
		if got.ID != want.id || got.Protocol != "geph" {
			t.Fatalf("per-exit outbound %d = %q (%s), want %q", i, got.ID, got.Protocol, want.id)
		}
		if host, _ := got.Config["exit_hostname"].(string); host != want.host {
			t.Fatalf("outbound %s exit_hostname = %q, want %q", got.ID, host, want.host)
		}
		if addr, _ := got.Config["address"].(string); addr != want.addr {
			t.Fatalf("outbound %s address = %q, want %q", got.ID, addr, want.addr)
		}
		if country, _ := got.Config["country"].(string); country != want.country {
			t.Fatalf("outbound %s country = %q, want %q", got.ID, country, want.country)
		}
		if tunnel, _ := got.Config["tunnel"].(string); tunnel != "geph-list" {
			t.Fatalf("outbound %s tunnel = %q, want geph-list", got.ID, tunnel)
		}
	}
}

// TestPerExitOutboundDialPinsClient verifies the per-exit dial path end to
// end through the outbound factory: the pinned dial lazily starts ONE client
// for the exit (shared across dials, serialized start), dials through it,
// and leaves the general outbound on the primary client.
func TestPerExitOutboundDialPinsClient(t *testing.T) {
	started := atomic.Int64{}
	fakeExit := &fakeClient{onDial: func(ctx context.Context, r string) (net.Conn, error) {
		return nil, errors.New("fake exit dial failure")
	}}
	p := &Provider{
		cfg:     providerConfig{OutboundID: "geph-pin"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	// Literal providers have no run goroutine; wire stop so Close's
	// <-p.stopped handshake (see Provider.Close) completes.
	p.stop = func() { close(p.stopped) }
	p.pinnedDialer = func(ctx context.Context, hostname string) (clientConn, error) {
		started.Add(1)
		if hostname != "tokyo1.example" {
			t.Errorf("pinnedDialer got hostname %q, want tokyo1.example", hostname)
		}
		return fakeExit, nil
	}
	p.mu.Lock()
	p.ready = true
	p.mu.Unlock()
	registerLiveProvider(p)
	defer unregisterLiveProvider(p)

	// The outbound factory parses the per-exit config form.
	f, ok := pub.Lookup("geph")
	if !ok {
		t.Fatal(`outbound protocol "geph" not registered`)
	}
	ob, err := f(map[string]any{
		"id":            "geph-pin-tokyo1.example",
		"tunnel":        "geph-pin",
		"exit_hostname": "tokyo1.example",
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	// The fake client reports a live session, so the dial rides through to
	// OpenConn and fails there — but the client was started exactly once
	// (lazily) and is cached.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, dialErr := ob.DialContext(ctx, pub.NetworkTCP, "example.com:80")
	if dialErr == nil {
		t.Fatal("dial should fail at the fake exit's OpenConn")
	}
	if started.Load() != 1 {
		t.Fatalf("pinnedDialer called %d times, want exactly 1 (lazy start, cached)", started.Load())
	}
	// The second dial reuses the cached client (no second start).
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	_, _ = ob.DialContext(ctx2, pub.NetworkTCP, "example.com:80")
	if started.Load() != 1 {
		t.Fatalf("pinnedDialer called %d times after a second dial, want still 1", started.Load())
	}

	// Close stops the pinned client with the provider.
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestDialExitRetriesFailedStart verifies a failed lazy start is retried
// after exitStartRetry instead of caching the failure forever.
func TestDialExitRetriesFailedStart(t *testing.T) {
	attempts := atomic.Int64{}
	p := &Provider{
		cfg:     providerConfig{OutboundID: "geph-retry"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	// The dial IS the retry: the pre-seeded state above is the cached
	// failure, and its startAt is past the retry window, so the first
	// pinnedDialer call must succeed and install the client.
	p.pinnedDialer = func(ctx context.Context, hostname string) (clientConn, error) {
		attempts.Add(1)
		return &fakeClient{onDial: func(ctx context.Context, remote string) (net.Conn, error) {
			return nil, errors.New("fake exit dial failure")
		}}, nil
	}
	p.mu.Lock()
	p.ready = true
	p.exitClients = map[string]*exitClientState{
		"exit1": {startErr: errors.New("previous failure"), startAt: time.Now().Add(-2 * exitStartRetry)},
	}
	p.mu.Unlock()

	// The dial fails at the fake exit's OpenConn, but the retry must have
	// started a client — the cached error is gone.
	_, err := p.dialExit(context.Background(), "exit1", "example.com:80")
	if err == nil {
		t.Fatal("dial should fail at the fake exit's OpenConn")
	}
	if attempts.Load() != 1 {
		t.Fatalf("pinnedDialer calls = %d, want 1 (retry after the cached failure)", attempts.Load())
	}
	p.mu.Lock()
	st := p.exitClients["exit1"]
	p.mu.Unlock()
	st.mu.Lock()
	hasClient := st.client != nil
	st.mu.Unlock()
	if !hasClient {
		t.Fatal("retry did not install a client after the cached failure")
	}
}

// TestRefreshExitsOnceNoBroker verifies the soft-failure contract: with no
// broker behind the client the roster stays empty and nothing panics (the
// general outbound is the whole set).
func TestRefreshExitsOnceNoBroker(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "geph-nobroker"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	p.refreshExitsOnce(context.Background(), nil)
	p.mu.Lock()
	n := len(p.exits)
	p.mu.Unlock()
	if n != 0 {
		t.Fatalf("exits = %d, want 0 without a broker", n)
	}
}

// countClient is a clientConn with a fixed session count, for status tests
// (fakeClient always reports 1; the status sums need variety).
type countClient struct{ sessions int }

func (c *countClient) OpenConn(ctx context.Context, remote string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (c *countClient) SessionCount() int { return c.sessions }
func (c *countClient) Close()            {}

// statusFixture returns a Provider whose state is set by mutate (under the
// provider lock), so Status() tests need no booted client stack. The config
// carries credentials on purpose: the status payload must never leak them.
func statusFixture(mutate func(p *Provider)) *Provider {
	p := &Provider{
		cfg: providerConfig{
			OutboundID: "geph-status",
			Secret:     "s3cret-value",
			Username:   "user-value",
			Password:   "pass-value",
		},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	p.mu.Lock()
	mutate(p)
	p.mu.Unlock()
	return p
}

// TestStatusReporting walks the Status() state machine and its details.
func TestStatusReporting(t *testing.T) {
	// Starting: a fresh provider, no client yet.
	st := statusFixture(func(p *Provider) {}).Status()
	if st.State != "starting" {
		t.Fatalf("starting: state=%q", st.State)
	}
	if st.Details["mode"] != "broker" {
		t.Fatalf("mode=%v, want broker by default", st.Details["mode"])
	}
	if st.Details["exits_in_roster"] != 0 {
		t.Fatalf("exits_in_roster=%v, want 0", st.Details["exits_in_roster"])
	}

	// Connecting: the client is up, no live session yet.
	st = statusFixture(func(p *Provider) {
		p.client = &countClient{sessions: 0}
		p.phase = "connecting"
	}).Status()
	if st.State != "connecting" || st.Message != "waiting for the first live session" {
		t.Fatalf("connecting: state=%q message=%q", st.State, st.Message)
	}
	if _, ok := st.Details["open_sessions"]; !ok {
		t.Fatal("connecting status must report open_sessions (even 0)")
	}

	// Running with a broker roster: ready flip, refresh bookkeeping, sessions.
	st = statusFixture(func(p *Provider) {
		p.ready = true
		p.phase = "running"
		p.readyAt = time.Now().Add(-time.Minute)
		p.client = &countClient{sessions: 2}
		p.exits = []exitInfo{{Hostname: "a.example"}, {Hostname: "b.example"}, {Hostname: "c.example"}}
		p.refreshAt = time.Now().Add(-5 * time.Minute)
	}).Status()
	if st.State != "running" || st.Message != "" {
		t.Fatalf("running: state=%q message=%q", st.State, st.Message)
	}
	if st.Details["exits_in_roster"] != 3 {
		t.Fatalf("exits_in_roster=%v, want 3", st.Details["exits_in_roster"])
	}
	if st.Details["open_sessions"] != 2 {
		t.Fatalf("open_sessions=%v, want 2", st.Details["open_sessions"])
	}
	for _, k := range []string{"ready_since", "last_roster_refresh"} {
		if _, ok := st.Details[k]; !ok {
			t.Fatalf("running status must report %s", k)
		}
	}

	// A roster failure is visible but never fatal.
	st = statusFixture(func(p *Provider) {
		p.ready = true
		p.phase = "running"
		p.readyAt = time.Now()
		p.refreshErr = errors.New("broker unreachable")
	}).Status()
	if st.State != "running" {
		t.Fatalf("roster_error must not flip the state: %q", st.State)
	}
	if st.Details["roster_error"] != "broker unreachable" {
		t.Fatalf("roster_error=%v", st.Details["roster_error"])
	}

	// A terminal startup error wins over the phase.
	st = statusFixture(func(p *Provider) {
		p.startErr = errors.New("bad config")
		p.client = &countClient{sessions: 1}
	}).Status()
	if st.State != "error" || st.Message != "bad config" {
		t.Fatalf("error: state=%q message=%q", st.State, st.Message)
	}

	// Stopped wins over everything, terminal errors included.
	st = statusFixture(func(p *Provider) {
		p.closed = true
		p.startErr = errors.New("bad config")
	}).Status()
	if st.State != "stopped" {
		t.Fatalf("stopped: state=%q", st.State)
	}

	// Pinned per-exit clients: hostnames listed sorted, session counts summed;
	// a state whose start failed contributes neither.
	st = statusFixture(func(p *Provider) {
		p.ready = true
		p.phase = "running"
		p.readyAt = time.Now()
		p.exitClients = map[string]*exitClientState{
			"zeta.example":   {client: &countClient{sessions: 1}},
			"alpha.example":  {client: &countClient{sessions: 3}},
			"failed.example": {},
		}
	}).Status()
	pinned, ok := st.Details["pinned_exits"].([]string)
	if !ok || len(pinned) != 2 || pinned[0] != "alpha.example" || pinned[1] != "zeta.example" {
		t.Fatalf("pinned_exits=%v", st.Details["pinned_exits"])
	}
	if st.Details["exit_client_sessions"] != 4 {
		t.Fatalf("exit_client_sessions=%v, want 4", st.Details["exit_client_sessions"])
	}

	// Credentials never leak into the status payload.
	raw, err := json.Marshal(statusFixture(func(p *Provider) {
		p.ready = true
		p.phase = "running"
		p.readyAt = time.Now()
	}).Status())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"s3cret-value", "user-value", "pass-value"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("status payload leaks credential %q: %s", secret, raw)
		}
	}
}

// TestStatusRunsConcurrently hammers Status against the mutating paths it
// snapshots (phase flips, ready flips, roster updates, the Outbounds reaper)
// for the race detector.
func TestStatusRunsConcurrently(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "geph-race"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	p.exitClients = map[string]*exitClientState{
		"alpha.example": {client: &countClient{sessions: 1}},
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = p.Status()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			p.setPhase("connecting")
			p.mu.Lock()
			p.ready = j%2 == 0
			p.exits = []exitInfo{{Hostname: "a.example"}}
			p.exitClients["zeta.example"] = &exitClientState{client: &countClient{sessions: 1}}
			p.mu.Unlock()
			p.Outbounds(context.Background())
		}
	}()
	wg.Wait()
}

// dialRecorder is a thread-safe record of dialed "network address" pairs,
// shared by the fake dialers below.
type dialRecorder struct {
	mu  sync.Mutex
	rec []string
}

func (r *dialRecorder) record(network, address string) {
	r.mu.Lock()
	r.rec = append(r.rec, network+" "+address)
	r.mu.Unlock()
}

func (r *dialRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.rec...)
}

// fakeUpstreamDialer is an UpstreamDialer stand-in for the injection tests:
// it records dials and answers with a dead pipe (the client speaks real
// protocols on top; the tests only assert the dial path).
type fakeUpstreamDialer struct{ rec *dialRecorder }

func (f fakeUpstreamDialer) DialUpstream(ctx context.Context, network, address string) (net.Conn, error) {
	f.rec.record(network, address)
	return deadPipe(ctx)
}

// fakeStackDialer is a StackDialer stand-in with the same recording shape.
type fakeStackDialer struct{ rec *dialRecorder }

func (f fakeStackDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.rec.record(network, address)
	return deadPipe(ctx)
}

// deadPipe returns one end of a net.Pipe whose pair is closed when ctx ends,
// so the returned "connections" never outlive the caller's context.
func deadPipe(ctx context.Context) (net.Conn, error) {
	a, b := net.Pipe()
	go func() {
		<-ctx.Done()
		a.Close()
		b.Close()
	}()
	return a, nil
}

// TestEngineDialerPrecedence verifies the dialer resolution: an injected
// upstream route (the spec's upstream_proxy naming a goose route) outranks
// the engine stack dialer, the stack takes the slot only without a route,
// and a bare config yields the system dialer.
func TestEngineDialerPrecedence(t *testing.T) {
	d, viaRoute := engineDialer(map[string]any{})
	if d != nil || viaRoute {
		t.Fatalf("bare config: dialer=%T viaRoute=%v, want nil,false", d, viaRoute)
	}

	routeRec, stackRec := &dialRecorder{}, &dialRecorder{}
	d, viaRoute = engineDialer(map[string]any{
		pub.UpstreamDialerKey: fakeUpstreamDialer{routeRec},
		pub.StackDialerKey:    fakeStackDialer{stackRec},
	})
	if !viaRoute {
		t.Fatal("route+stack: viaRoute=false, want true")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := d(ctx, "tcp", "broker.example:7000"); err != nil {
		t.Fatalf("route dial: %v", err)
	}
	if got := routeRec.recorded(); len(got) != 1 || got[0] != "tcp broker.example:7000" {
		t.Fatalf("route dials = %v, want exactly the one dial", got)
	}
	if got := stackRec.recorded(); len(got) != 0 {
		t.Fatalf("engine stack dialed although a route was injected: %v", got)
	}

	stackOnly := &dialRecorder{}
	d, viaRoute = engineDialer(map[string]any{
		pub.StackDialerKey: fakeStackDialer{stackOnly},
	})
	if d == nil || viaRoute {
		t.Fatalf("stack-only: dialer set=%t viaRoute=%v, want dialer,false", d != nil, viaRoute)
	}
	if _, err := d(ctx, "tcp", "broker.example:7000"); err != nil {
		t.Fatalf("stack dial: %v", err)
	}
	if got := stackOnly.recorded(); len(got) != 1 {
		t.Fatalf("stack dials = %v, want exactly the one dial", got)
	}
}

// TestNewProviderRouteCarriesClientDials verifies the factory behavior: with
// an injected engine route the client's own dials (the pinned exit's route
// tree) ride the route — observable on the fake's recorder — and Status
// reports engine_route, not engine_stack.
func TestNewProviderRouteCarriesClientDials(t *testing.T) {
	routeRec, stackRec := &dialRecorder{}, &dialRecorder{}
	p, err := NewProvider(map[string]any{
		"outbound_id":         "geph-route",
		"exit_constraint":     map[string]any{"direct": "127.0.0.1:1/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, // nothing answers; the client retries
		pub.UpstreamDialerKey: fakeUpstreamDialer{routeRec},
		pub.StackDialerKey:    fakeStackDialer{stackRec},
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	prov := p.(*Provider)
	defer prov.Close()

	if !prov.viaRoute {
		t.Fatal("provider does not record the injected route")
	}
	if prov.engineDialer == nil {
		t.Fatal("provider has no engine dialer threaded")
	}

	// The session manager dials the pinned exit through the route and keeps
	// retrying (nothing answers on the dead pipe); poll for the first dial.
	deadline := time.Now().Add(10 * time.Second)
	for len(routeRec.recorded()) == 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if got := routeRec.recorded(); len(got) == 0 {
		t.Fatal("the client never dialed through the injected route")
	}
	if got := stackRec.recorded(); len(got) != 0 {
		t.Fatalf("engine stack dialed although a route was injected: %v", got)
	}

	st := prov.Status()
	if st.Details["engine_route"] != true {
		t.Fatalf("Status engine_route = %v, want true", st.Details["engine_route"])
	}
	if st.Details["engine_stack"] != false {
		t.Fatalf("Status engine_stack = %v, want false under a route", st.Details["engine_stack"])
	}
}
