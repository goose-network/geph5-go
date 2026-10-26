package geph

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
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
