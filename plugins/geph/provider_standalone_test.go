// Standalone end-to-end test for the geph provider: NO external geph5 exit,
// no Rust binary, no env vars — the exit runs in the same process via the
// provider's "embedded_exit" option (internal/exitlib). This is the "just
// one process" deployment shape: the geph plugin alone embeds the geph5-go
// client AND the geph5-go exit, and a dial rides the full chain in memory:
//
//	HTTP client → "geph" outbound DialContext → session manager OpenConn →
//	  X25519+ed25519 handshake → picomux tunnel → embedded exit → target
//
// with no listener anywhere in the path — the outbound calls the provider in
// process. The test runs in the default suite (no build tag); it takes ~20s
// because session establishment waits for a live tunnel.
package geph

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	pub "github.com/goose-network/goose-plugin-api"
)

func TestGephProviderStandalone(t *testing.T) {
	// 1. The "internet": an HTTP server on loopback.
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetPort := targetLn.Addr().(*net.TCPAddr).Port
	targetAddr := fmt.Sprintf("127.0.0.1:%d", targetPort)
	bigBody := bigResponseBody(t)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/via-geph":
			fmt.Fprintf(w, "standalone-e2e:%s", r.URL.Path)
		case "/big":
			w.Write(bigBody)
		default:
			http.NotFound(w, r)
		}
	})}
	go srv.Serve(targetLn)
	defer srv.Close()

	// 2. The provider in standalone mode: embedded_exit boots the exit
	//    in-process (allow_loopback so it can reach the loopback target; a
	//    deployed exit would face the real internet) and pins the client at it.
	p, err := NewProvider(map[string]any{
		"embedded_exit": map[string]any{"allow_loopback": true},
		"secret":        "standalone-test",
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	defer p.(*Provider).Close()

	// 3. Wait for the ready flip (embedded exit up + client session live),
	//    then build the "geph" outbound from the advertised config — exactly
	//    what the engine's router does.
	factory, ok := pub.Lookup("geph")
	if !ok {
		t.Fatal(`outbound protocol "geph" not registered`)
	}
	var ob pub.Outbound
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		outs, err := p.Outbounds(context.Background())
		if err != nil {
			t.Fatalf("Outbounds: %v", err)
		}
		if len(outs) > 0 {
			ob, err = factory(outs[0].Config)
			if err != nil {
				t.Fatalf("outbound factory: %v", err)
			}
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if ob == nil {
		t.Fatal("provider never became ready")
	}
	t.Logf("provider ready: outbound %s (%s)", ob.ID(), ob.Address())

	// 4. Real HTTP through the in-process dial path — no listener, no
	//    loopback hop: outbound → client tunnels → the embedded exit → the
	//    loopback target.
	body := httpGetViaOutbound(t, ob, "127.0.0.1", int(targetPort), "/via-geph", targetAddr)
	if string(body) != "standalone-e2e:/via-geph" {
		t.Fatalf("body = %q", string(body))
	}
	t.Logf("body through embedded-exit tunnel ok (%d bytes)", len(body))

	// 5. A 192 KiB response: multi-frame picomux relaying through the
	//    embedded exit, both directions.
	big := httpGetViaOutbound(t, ob, "127.0.0.1", int(targetPort), "/big", targetAddr)
	if !bytesEqual(big, bigBody) {
		t.Fatalf("big body mismatch: got %d, want %d", len(big), len(bigBody))
	}
	t.Logf("192KiB through embedded-exit tunnel ok (%d bytes)", len(big))
}
