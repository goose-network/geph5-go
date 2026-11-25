package geph

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// TestExitUsable checks the freemium access predicate: a free account needs
// "Free" among an exit's advertised levels, a Plus account needs "Plus", and an
// exit with no advertised policy is always usable (missing metadata must not
// silently narrow discovery).
func TestExitUsable(t *testing.T) {
	cases := []struct {
		levels []string
		isPlus bool
		want   bool
	}{
		{[]string{"Plus", "Free"}, false, true},
		{[]string{"Plus", "Free"}, true, true},
		{[]string{"Plus"}, false, false},
		{[]string{"Plus"}, true, true},
		{[]string{"Free"}, false, true},
		{[]string{"Free"}, true, false},
		{nil, false, true},
		{[]string{}, true, true},
	}
	for _, c := range cases {
		if got := exitUsable(c.levels, c.isPlus); got != c.want {
			t.Errorf("exitUsable(%v, isPlus=%v) = %v, want %v", c.levels, c.isPlus, got, c.want)
		}
	}
}

// levelClient is a clientConn that also reports a configurable account tier, so
// tests can exercise the per-provider exit-eligibility gate without a live
// client. Embedding fakeClient supplies the dial/session/close surface; the gate
// never dials, so onDial may be nil.
type levelClient struct {
	fakeClient
	isPlus bool
	known  bool
}

func (c *levelClient) AccountLevel() (bool, bool) { return c.isPlus, c.known }

// TestOutboundsAdvertisesAllExitsWithLevels verifies the advertised roster is a
// stable discovery surface: every discovered exit is listed regardless of the
// account's tier, with its allowed_levels carried in Config. Filtering exits out
// of Outbounds would make the engine delete their outbound ids and silently
// truncate any chain pinned to them (the router skips unknown references), so
// eligibility is enforced at the dial gate instead — see TestCheckExitTier.
func TestOutboundsAdvertisesAllExitsWithLevels(t *testing.T) {
	p := &Provider{
		cfg:     providerConfig{OutboundID: "geph"},
		watchCh: make(chan struct{}, 1),
		stopped: make(chan struct{}),
	}
	p.mu.Lock()
	p.ready = false
	p.exits = []exitInfo{
		{Hostname: "free1", C2EListen: "1.1.1.1:1", AllowedLevels: []string{"Plus", "Free"}},
		{Hostname: "plus1", C2EListen: "2.2.2.2:2", AllowedLevels: []string{"Plus"}},
		{Hostname: "unknown1", C2EListen: "3.3.3.3:3"},
	}
	p.mu.Unlock()

	out, err := p.Outbounds(context.Background())
	if err != nil {
		t.Fatalf("Outbounds: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("got %d outbounds, want 3 (all exits advertised, none filtered)", len(out))
	}
	levels := map[string][]string{}
	for _, o := range out {
		h := o.Config["exit_hostname"].(string)
		if al, ok := o.Config["allowed_levels"].([]string); ok {
			levels[h] = al
		}
	}
	if len(levels["plus1"]) != 1 || levels["plus1"][0] != "Plus" {
		t.Fatalf("plus1 allowed_levels = %v, want [Plus]", levels["plus1"])
	}
	if len(levels["free1"]) != 2 {
		t.Fatalf("free1 allowed_levels = %v, want [Plus Free]", levels["free1"])
	}
}

// TestAccountLevelReadsProviderClient verifies the provider reads its OWN
// client's tier: a nil client or a clientConn without the AccountLevel capability
// reports unknown, and a client that reports a tier is read verbatim.
func TestAccountLevelReadsProviderClient(t *testing.T) {
	p := &Provider{watchCh: make(chan struct{}, 1), stopped: make(chan struct{})}
	if isPlus, known := p.accountLevel(); isPlus || known {
		t.Fatalf("nil client: got (%v,%v), want (false,false)", isPlus, known)
	}
	p.client = &fakeClient{} // no AccountLevel capability
	if _, known := p.accountLevel(); known {
		t.Fatal("fakeClient (no AccountLevel): want unknown")
	}
	p.client = &levelClient{isPlus: true, known: true}
	if isPlus, known := p.accountLevel(); !isPlus || !known {
		t.Fatalf("levelClient: got (%v,%v), want (true,true)", isPlus, known)
	}
}

// TestCheckExitTier walks the dial-gate decision: a known tier rejects an exit
// whose allowed levels exclude it, an unknown tier (warmup) never rejects, and
// empty levels are always usable.
func TestCheckExitTier(t *testing.T) {
	cases := []struct {
		name    string
		isPlus  bool
		known   bool
		levels  []string
		wantErr bool
	}{
		{"free_plus_only_rejected", false, true, []string{"Plus"}, true},
		{"free_free_admitting_ok", false, true, []string{"Plus", "Free"}, false},
		{"plus_plus_only_ok", true, true, []string{"Plus"}, false},
		{"plus_free_only_rejected", true, true, []string{"Free"}, true},
		{"warmup_free_never_rejects", false, false, []string{"Plus"}, false},
		{"warmup_plus_never_rejects", true, false, []string{"Free"}, false},
		{"empty_levels_always_ok", false, true, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := &Provider{watchCh: make(chan struct{}, 1), stopped: make(chan struct{})}
			p.client = &levelClient{isPlus: c.isPlus, known: c.known}
			err := p.checkExitTier("x", c.levels)
			if (err != nil) != c.wantErr {
				t.Fatalf("checkExitTier(%v, isPlus=%v, known=%v) err=%v, wantErr=%v", c.levels, c.isPlus, c.known, err, c.wantErr)
			}
		})
	}
}

// TestCheckExitTierMessageAccurate verifies the diagnostic names the exit's
// actual allowed levels and the account's actual tier — correct even for a Plus
// account on a Free-only exit (the old hardcoded "account is Free" was doubly
// false there).
func TestCheckExitTierMessageAccurate(t *testing.T) {
	p := &Provider{watchCh: make(chan struct{}, 1), stopped: make(chan struct{})}
	p.client = &levelClient{isPlus: true, known: true}
	err := p.checkExitTier("freeonly", []string{"Free"})
	if err == nil {
		t.Fatal("expected rejection for a Plus account on a Free-only exit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "this account is Plus") || !strings.Contains(msg, "[Free]") {
		t.Fatalf("message misdescribes the mismatch: %q", msg)
	}
	if strings.Contains(msg, "account is Free") {
		t.Fatalf("message falsely claims the account is Free: %q", msg)
	}
}

// TestCheckExitTierIsPerProvider is the regression test for cross-provider
// contamination: two providers co-hosted in one process (a Free account and a
// Plus account) each gate on their OWN client's tier, not a shared process
// global. The old auth.ISPlus-based gate read whichever client wrote last, so a
// Free provider could advertise/dial Plus-only exits and a Plus provider could
// be told its account is Free.
func TestCheckExitTierIsPerProvider(t *testing.T) {
	free := &Provider{watchCh: make(chan struct{}, 1), stopped: make(chan struct{})}
	free.client = &levelClient{isPlus: false, known: true}
	plus := &Provider{watchCh: make(chan struct{}, 1), stopped: make(chan struct{})}
	plus.client = &levelClient{isPlus: true, known: true}

	plusOnly := []string{"Plus"}
	if err := free.checkExitTier("e", plusOnly); err == nil {
		t.Fatal("Free provider should reject a Plus-only exit")
	}
	if err := plus.checkExitTier("e", plusOnly); err != nil {
		t.Fatalf("Plus provider should accept a Plus-only exit: %v", err)
	}
}
