package brokerproto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestLiveNetStatusArtifact decodes and cryptographically verifies a REAL
// broker.geph.io get_net_status response captured at /tmp/netstatus.json. This
// is the definitive arbiter for the JsonSigned / NetStatusEntry integer-array
// wire codec: a self-minted round-trip would hide a symmetric format bug, but
// the broker's actual ed25519 signature over the byte-exact inner_literal does
// not. Skipped when the artifact is absent (it is a local probe, not CI data).
func TestLiveNetStatusArtifact(t *testing.T) {
	raw, err := os.ReadFile("/tmp/netstatus.json")
	if err != nil {
		t.Skipf("live artifact absent: %v", err)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	var signed JsonSigned
	if err := json.Unmarshal(env.Result, &signed); err != nil {
		t.Fatalf("decode JsonSigned (int-array pubkey/signature): %v", err)
	}
	if len(signed.Pubkey) != 32 {
		t.Fatalf("pubkey len = %d, want 32", len(signed.Pubkey))
	}
	if len(signed.Signature) != 64 {
		t.Fatalf("signature len = %d, want 64", len(signed.Signature))
	}
	const master = "88c1d2d4197bed815b01a22cadfc6c35aa246dddb553682037a118aebfaa3954"
	if got := signed.PubkeyHex(); got != master {
		t.Fatalf("pubkey hex = %s, want broker master %s", got, master)
	}
	var status NetStatus
	validator := func(pk [32]byte) bool { return hex.EncodeToString(pk[:]) == master }
	if err := signed.Verify(DomainNetStatus, validator, &status); err != nil {
		t.Fatalf("Verify real broker signature: %v", err)
	}
	if len(status.Exits) == 0 {
		t.Fatal("no exits decoded")
	}
	for host, e := range status.Exits {
		if len(e.Pubkey) != 32 {
			t.Fatalf("exit %s: pubkey len %d, want 32", host, len(e.Pubkey))
		}
		if e.Exit.C2EListen == "" {
			t.Fatalf("exit %s: empty c2e_listen", host)
		}
		if host != hex.EncodeToString(e.Pubkey) {
			t.Fatalf("exit key %s != pubkey hex %s", host, hex.EncodeToString(e.Pubkey))
		}
	}
	t.Logf("verified real broker net_status: %d exits, signature OK", len(status.Exits))

	// Codec symmetry: re-marshal (now int arrays) and re-verify.
	reMarshaled, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("re-marshal JsonSigned: %v", err)
	}
	var again JsonSigned
	if err := json.Unmarshal(reMarshaled, &again); err != nil {
		t.Fatalf("re-decode JsonSigned: %v", err)
	}
	var status2 NetStatus
	if err := again.Verify(DomainNetStatus, validator, &status2); err != nil {
		t.Fatalf("re-verify after round-trip: %v", err)
	}
}

// TestConnTestWireKey checks the ConnTest variant uses the Rust snake_case wire
// key "conn_test" while keeping the internal Kind "conntest", and that the
// legacy "conntest" key still decodes (route-cache backward compat).
func TestConnTestWireKey(t *testing.T) {
	lower := RouteDescriptor{Kind: "tcp", TcpAddr: "1.2.3.4:443"}
	r := RouteDescriptor{Kind: "conntest", PingCount: 3, Lower: &lower}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if _, ok := m["conn_test"]; !ok {
		t.Fatalf("wire key conn_test absent: %s", b)
	}
	if _, ok := m["conntest"]; ok {
		t.Fatalf("legacy wire key conntest must not be emitted: %s", b)
	}
	var back RouteDescriptor
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("decode conn_test: %v", err)
	}
	if back.Kind != "conntest" || back.PingCount != 3 || back.Lower == nil || back.Lower.TcpAddr != "1.2.3.4:443" {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
	// Legacy alias still decodes.
	var legacy RouteDescriptor
	if err := json.Unmarshal([]byte(`{"conntest":{"ping_count":1,"lower":{"tcp":"5.6.7.8:1"}}}`), &legacy); err != nil {
		t.Fatalf("decode legacy conntest: %v", err)
	}
	if legacy.Kind != "conntest" {
		t.Fatalf("legacy alias kind = %q", legacy.Kind)
	}
}

// TestExitRouteDescriptorIntArray checks exit_pubkey decodes from the
// ed25519-dalek integer-array form (the data-path get_exit_route inner value).
func TestExitRouteDescriptorIntArray(t *testing.T) {
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = byte(i + 1)
	}
	wire := map[string]any{
		"exit_pubkey": pk, // json.Marshal([]byte) -> base64; force int array below
		"exit":        ExitDescriptor{C2EListen: "9.9.9.9:1", Country: "US", Expiry: 1},
		"route":       RouteDescriptor{Kind: "tcp", TcpAddr: "9.9.9.9:1"},
	}
	// Build the integer-array form explicitly (what the broker sends).
	arr := make([]int, 32)
	for i, v := range pk {
		arr[i] = int(v)
	}
	wire["exit_pubkey"] = arr
	b, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal wire: %v", err)
	}
	var r ExitRouteDescriptor
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("decode ExitRouteDescriptor int-array exit_pubkey: %v", err)
	}
	if hex.EncodeToString(r.ExitPubkey) != hex.EncodeToString(pk) {
		t.Fatalf("exit_pubkey mismatch: %x", r.ExitPubkey)
	}
	if r.Exit.C2EListen != "9.9.9.9:1" || r.Route.Kind != "tcp" {
		t.Fatalf("inner decode mismatch: %+v", r)
	}
}