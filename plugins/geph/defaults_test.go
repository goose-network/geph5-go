package geph

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestBuildClientConfigZeroConfigDefaults verifies the embedded production
// defaults: a genuinely-empty provider config synthesizes the auto exit
// constraint, the direct production broker, and its verification keys — so the
// client boots and retrieves the exit roster with no operator-supplied file,
// like psiphon's embedded config.
func TestBuildClientConfigZeroConfigDefaults(t *testing.T) {
	cfg, err := buildClientConfig(providerConfig{})
	if err != nil {
		t.Fatalf("buildClientConfig: %v", err)
	}
	if cfg.ExitConstraint.Kind != "auto" {
		t.Fatalf("exit constraint = %+v, want auto", cfg.ExitConstraint)
	}
	if cfg.Broker == nil || cfg.Broker.Kind != "direct" || cfg.Broker.Direct != defaultBrokerURL {
		t.Fatalf("broker = %+v, want direct %s", cfg.Broker, defaultBrokerURL)
	}
	if cfg.BrokerKeys == nil {
		t.Fatal("broker keys not embedded")
	}
	if cfg.BrokerKeys.Master != defaultBrokerKeys.Master ||
		cfg.BrokerKeys.MizaruFree != defaultBrokerKeys.MizaruFree ||
		cfg.BrokerKeys.MizaruPlus != defaultBrokerKeys.MizaruPlus ||
		cfg.BrokerKeys.MizaruBw != defaultBrokerKeys.MizaruBw {
		t.Fatalf("broker keys = %+v, want the embedded production keys", cfg.BrokerKeys)
	}
	// No credential is embedded: geph is freemium, the roster needs none, and a
	// tunnel session awaits an operator-supplied secret.
	if cfg.Credentials.Kind != "" {
		t.Fatalf("credentials = %+v, want none embedded", cfg.Credentials)
	}
}

// TestZeroConfigProductionPredicate walks the cases the defaults apply to: only
// the genuinely-empty production config qualifies; any explicit mode (static
// YAML, inline constraint/broker, enabled embedded exit) opts out.
func TestZeroConfigProductionPredicate(t *testing.T) {
	cases := []struct {
		name string
		pc   providerConfig
		want bool
	}{
		{"empty", providerConfig{}, true},
		{"outbound_id_only", providerConfig{OutboundID: "geph"}, true},
		{"secret_only", providerConfig{Secret: "s"}, true},
		{"embedded_exit_false", providerConfig{EmbeddedExit: json.RawMessage(`false`)}, true},
		{"config_path", providerConfig{ConfigPath: "/tmp/x.yaml"}, false},
		{"exit_constraint", providerConfig{ExitConstraint: json.RawMessage(`"auto"`)}, false},
		{"broker", providerConfig{Broker: json.RawMessage(`"https://b.example"`)}, false},
		{"embedded_exit_true", providerConfig{EmbeddedExit: json.RawMessage(`true`)}, false},
		{"embedded_exit_object", providerConfig{EmbeddedExit: json.RawMessage(`{"allow_loopback":true}`)}, false},
		{"embedded_exit_malformed", providerConfig{EmbeddedExit: json.RawMessage(`{bad`)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := zeroConfigProduction(tc.pc); got != tc.want {
				t.Fatalf("zeroConfigProduction = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDefaultsDoNotOverrideDirectMode verifies a direct-pinned config (no
// broker by design) is left untouched: the defaults must not inject a broker or
// keys into a setup that deliberately skips the broker.
func TestDefaultsDoNotOverrideDirectMode(t *testing.T) {
	cfg, err := buildClientConfig(providerConfig{
		ExitConstraint: json.RawMessage(`{"direct":"127.0.0.1:9111/deadc0de"}`),
		Secret:         "hunter2",
	})
	if err != nil {
		t.Fatalf("buildClientConfig: %v", err)
	}
	if cfg.Broker != nil {
		t.Fatalf("direct mode gained a broker: %+v", cfg.Broker)
	}
	if cfg.BrokerKeys != nil {
		t.Fatalf("direct mode gained broker keys: %+v", cfg.BrokerKeys)
	}
	if cfg.ExitConstraint.Kind != "direct" {
		t.Fatalf("exit constraint = %+v, want direct", cfg.ExitConstraint)
	}
}

// TestDefaultsDoNotOverrideCustomBroker verifies an explicit broker and keys
// are preserved verbatim — the defaults never replace operator-chosen network
// parameters (a custom broker may use different verification keys).
func TestDefaultsDoNotOverrideCustomBroker(t *testing.T) {
	cfg, err := buildClientConfig(providerConfig{
		ExitConstraint: json.RawMessage(`"auto"`),
		Broker:         json.RawMessage(`"https://broker.example/geph5-broker"`),
		BrokerKeys:     json.RawMessage(`{"master":"aa","mizaru_free":"bb","mizaru_plus":"cc","mizaru_bw":"dd"}`),
	})
	if err != nil {
		t.Fatalf("buildClientConfig: %v", err)
	}
	if cfg.Broker.Direct != "https://broker.example/geph5-broker" {
		t.Fatalf("broker = %+v, want the custom broker", cfg.Broker)
	}
	if cfg.BrokerKeys.Master != "aa" || cfg.BrokerKeys.MizaruBw != "dd" {
		t.Fatalf("broker keys = %+v, want the custom keys", cfg.BrokerKeys)
	}
}

// TestDefaultsDoNotOverrideConfigPath verifies a static YAML base is not given
// the embedded broker: config_path opts out of the zero-config defaults even
// when the YAML itself carries no broker.
func TestDefaultsDoNotOverrideConfigPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geph5.yaml")
	yaml := []byte("exit_constraint: auto\ncredentials: test_dummy\n")
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := buildClientConfig(providerConfig{ConfigPath: path})
	if err != nil {
		t.Fatalf("buildClientConfig: %v", err)
	}
	if cfg.Broker != nil {
		t.Fatalf("config_path base gained the embedded broker: %+v", cfg.Broker)
	}
	if cfg.BrokerKeys != nil {
		t.Fatalf("config_path base gained embedded keys: %+v", cfg.BrokerKeys)
	}
}

// TestOutboundsEmitRosterWhileConnecting verifies the roster is advertised
// independent of session readiness: with a stored exit roster but no live
// session (the credential-less zero-config state), Outbounds emits the per-exit
// outbounds — the discovered servers — without the general outbound, which
// awaits a session. This is the geph analogue of psiphon emitting its datastore
// servers without waiting for the main tunnel.
func TestOutboundsEmitRosterWhileConnecting(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "geph-list"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	p.mu.Lock()
	p.ready = false // no live session yet
	p.exits = []exitInfo{
		{Hostname: "tokyo1.example", C2EListen: "1.2.3.4:7000", Country: "JP"},
		{Hostname: "berlin1.example", C2EListen: "5.6.7.8:7001", Country: "DE"},
	}
	p.mu.Unlock()

	out, err := p.Outbounds(context.Background())
	if err != nil {
		t.Fatalf("Outbounds: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d outbounds, want 2 (per-exit only, no general while connecting)", len(out))
	}
	for _, o := range out {
		if _, pinned := o.Config["exit_hostname"]; !pinned {
			t.Fatalf("outbound %q is not a per-exit pin (general outbound leaked while connecting)", o.ID)
		}
	}
	if out[0].ID != "geph-list-berlin1.example-5.6.7.8:7001" || out[1].ID != "geph-list-tokyo1.example-1.2.3.4:7000" {
		t.Fatalf("per-exit outbounds not sorted: %q, %q", out[0].ID, out[1].ID)
	}
}
