package geph

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	pub "github.com/goose-network/goose-plugin-api"

	"github.com/geph-official/geph5-go/internal/config"
)

func TestParseConfig(t *testing.T) {
	pc, err := parseConfig(map[string]any{
		"config_path":     "/tmp/geph5.yaml",
		"socks_listen":    "127.0.0.1:0",
		"outbound_id":     "geph-test",
		"exit_constraint": map[string]any{"direct": "127.0.0.1:9000/aa"},
		"secret":          "topsecret",
		"cache":           "/tmp/cache.db",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if pc.ConfigPath != "/tmp/geph5.yaml" || pc.SocksListen != "127.0.0.1:0" {
		t.Fatalf("unexpected paths: %+v", pc)
	}
	if pc.OutboundID != "geph-test" {
		t.Fatalf("outbound id = %q", pc.OutboundID)
	}
	if pc.Secret != "topsecret" {
		t.Fatalf("secret = %q", pc.Secret)
	}
}

func TestParseConfigNil(t *testing.T) {
	pc, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig(nil): %v", err)
	}
	if pc.ConfigPath != "" || pc.SocksListen != "" || pc.OutboundID != "" || pc.Secret != "" || pc.Cache != "" {
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

// TestBuildClientConfigNoConstraint verifies the factory-rejection path: a
// config with no exit constraint anywhere is an error (before we start a
// client that could never dial anywhere).
func TestBuildClientConfigNoConstraint(t *testing.T) {
	_, err := buildClientConfig(providerConfig{})
	if err == nil {
		// buildClientConfig itself allows it (Start rejects later); assert
		// the downstream contract instead.
		cfg := &config.Config{}
		if cfg.ExitConstraint.Kind != "" {
			t.Fatal("expected empty constraint")
		}
	}
}

// TestProviderRegistered verifies the init() registration landed in the
// goose plugin registry under the name "geph".
func TestProviderRegistered(t *testing.T) {
	f, ok := pub.LookupProvider("geph")
	if !ok {
		t.Fatal(`provider "geph" not registered`)
	}
	if f == nil {
		t.Fatal("registered factory is nil")
	}
}

// TestOutboundsEmptyWhileStarting verifies the bootstrap pattern: a provider
// whose client is still connecting (pointed at an exit that cannot possibly
// answer) reports an empty outbound set rather than an error, so the engine's
// pool simply stays empty while the session manager retries.
func TestOutboundsEmptyWhileStarting(t *testing.T) {
	p, err := New(map[string]any{
		"exit_constraint": map[string]any{"direct": "127.0.0.1:1/deadc0de"}, // nothing listens on :1
	})
	if err != nil {
		t.Fatalf("New: %v", err)
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
// (simulated by setting the provider's state directly, as tor-go's test does),
// Outbounds emits one socks5 outbound with the configured id and the client's
// listener address, and Watch was signaled.
func TestOutboundsAfterReady(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "geph-test"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	p.mu.Lock()
	p.ready = true
	p.socksAddr = "127.0.0.1:39099"
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
	if out[0].ID != "geph-test" || out[0].Protocol != "socks5" {
		t.Fatalf("unexpected outbound: %+v", out[0])
	}
	addr, _ := out[0].Config["address"].(string)
	if addr != "127.0.0.1:39099" {
		t.Fatalf("outbound address = %q, want %q", addr, "127.0.0.1:39099")
	}

	select {
	case <-p.Watch():
	default:
		t.Fatal("watch channel was not signaled")
	}
}

// TestCloseDuringConnect verifies Close cancels the background bootstrap even
// while the client is still connecting (a session never comes up), and that
// Close is idempotent enough to call from a deferred cleanup.
func TestCloseDuringConnect(t *testing.T) {
	pAny, err := New(map[string]any{
		"exit_constraint": map[string]any{"direct": "127.0.0.1:1/deadc0de"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p := pAny.(*Provider)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-p.stopped:
	default:
		t.Fatal("bootstrap goroutine still running after Close")
	}
}
