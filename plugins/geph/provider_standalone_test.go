// Standalone end-to-end test for the geph provider: NO external geph5 exit,
// no Rust binary, no env vars — the exit runs in the same process via the
// provider's "embedded_exit" option (internal/exitlib). This is the "just
// one process" deployment shape: the geph plugin alone embeds the geph5-go
// client AND the geph5-go exit, and a SOCKS5 CONNECT rides the full chain
//
//	HTTP client → plugin's client SOCKS5 → session manager →
//	  X25519+ed25519 handshake → picomux tunnel → embedded exit → target
//
// all inside one process. The test runs in the default suite (no build tag);
// it takes ~20s because session establishment waits for a live tunnel.
package geph

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
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
	p, err := New(map[string]any{
		"embedded_exit": map[string]any{"allow_loopback": true},
		"secret":        "standalone-test",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.(*Provider).Close()

	// 3. Wait for the ready flip (embedded exit up + client session live),
	//    then pull the advertised outbound.
	var socksAddr string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		outs, err := p.Outbounds(context.Background())
		if err != nil {
			t.Fatalf("Outbounds: %v", err)
		}
		if len(outs) > 0 {
			if addr, ok := outs[0].Config["address"].(string); ok {
				socksAddr = addr
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if socksAddr == "" {
		t.Fatal("provider never became ready")
	}
	t.Logf("provider ready: SOCKS5 at %s", socksAddr)

	// 4. Real HTTP through the plugin's SOCKS5 listener → client tunnels →
	//    the embedded exit → the loopback target.
	body := httpGetViaSocks5(t, socksAddr, "127.0.0.1", int(targetPort), "/via-geph", targetAddr)
	if string(body) != "standalone-e2e:/via-geph" {
		t.Fatalf("body = %q", string(body))
	}
	t.Logf("body through embedded-exit tunnel ok (%d bytes)", len(body))

	// 5. A 192 KiB response: multi-frame picomux relaying through the
	//    embedded exit, both directions.
	big := httpGetViaSocks5(t, socksAddr, "127.0.0.1", int(targetPort), "/big", targetAddr)
	if !bytesEqual(big, bigBody) {
		t.Fatalf("big body mismatch: got %d, want %d", len(big), len(bigBody))
	}
	t.Logf("192KiB through embedded-exit tunnel ok (%d bytes)", len(big))
}
