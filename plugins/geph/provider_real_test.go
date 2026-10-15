//go:build geph_real || geph_e2e

// Real-network end-to-end test for the geph provider: it connects the embedded
// geph5 client to a REAL geph5 exit (the Rust geph5-exit binary) and pushes
// real HTTP traffic through the full stack:
//
//	HTTP client → SOCKS5 CONNECT → embedded client (provider) →
//	  session manager → X25519+ed25519 handshake → picomux tunnel →
//	  Rust geph5-exit c2e listener → target HTTP server
//
// Gated behind the "geph_real" build tag because it needs the exit binary; run
// it with:
//
//	GEPH_EXIT_BIN=/path/to/geph5-exit go test -tags geph_real ./plugins/geph/
//
// Optionally set GEPH_TEST_TARGET=host:port (e.g. 223.5.5.5:80) to ALSO push a
// request to a real internet host through the tunnel.
package geph

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	pub "github.com/goose-network/goose-plugin-api"
)

const (
	envExitBin   = "GEPH_EXIT_BIN"
	envTargetURL = "GEPH_TEST_TARGET"
)

// mappedV4Loopback is the IPv4-mapped IPv6 literal for 127.0.0.1. The exit
// refuses to proxy to any non-globally-routable address (allow.rs), which
// rules out plain 127.0.0.1 targets — but its IPv6 routability check only
// rejects loopback/unspecified/multicast/unique-local/link-local, and an
// IPv4-mapped address is none of those. The kernel then maps ::ffff:127.0.0.1
// right back onto IPv4 loopback when the exit dials it, so a plain HTTP server
// bound to 127.0.0.1 receives the connection. The traffic is real end to end:
// a real exit process, a real TCP dial, the full tunnel — only the final hop
// lands on loopback.
const mappedV4Loopback = "::ffff:127.0.0.1"

// TestRealGephProviderThroughExit is the real e2e: exit binary + provider + a
// SOCKS5 CONNECT carrying real HTTP requests, tunneled through the exit.
func TestRealGephProviderThroughExit(t *testing.T) {
	bin := os.Getenv(envExitBin)
	if bin == "" {
		t.Fatalf("set %s to the geph5-exit binary path", envExitBin)
	}

	// 1. A plain HTTP target on loopback (the "internet" the exit reaches via
	//    the IPv4-mapped literal; see mappedV4Loopback).
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
			fmt.Fprintf(w, "geph-e2e:%s", r.URL.Path)
		case "/big":
			w.Write(bigBody)
		default:
			http.NotFound(w, r)
		}
	})}
	go srv.Serve(targetLn)
	defer srv.Close()

	// 2. Generate the exit's signing secret and config; boot the exit with NO
	//    broker section (its handle_client then skips credential verification).
	//    The secret file is PRE-created with a known seed so the test knows the
	//    exit's public key for the direct constraint.
	dir := t.TempDir()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(dir, "signing_secret")
	if err := os.WriteFile(secretPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	c2e, b2e := freeLocalPort(t), freeLocalPort(t)
	cfgPath := filepath.Join(dir, "exit.yaml")
	cfg := fmt.Sprintf(`
signing_secret: %s
c2e_listen: 127.0.0.1:%d
b2e_listen: 127.0.0.1:%d
country: US
city: test
`, secretPath, c2e, b2e)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	exitCmd := exec.Command(bin, "--config", cfgPath)
	exitLog, _ := os.Create(filepath.Join(dir, "exit.log"))
	exitCmd.Stdout, exitCmd.Stderr = exitLog, exitLog
	if err := exitCmd.Start(); err != nil {
		t.Fatalf("start geph5-exit: %v", err)
	}
	defer func() {
		_ = exitCmd.Process.Kill()
		_, _ = exitCmd.Process.Wait()
		exitLog.Close()
	}()
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", c2e), 30*time.Second, "exit c2e listener")

	// 3. The exit's ed25519 public key, derived from the seed we pre-created.
	pubHex, err := readExitPubkey(secretPath)
	if err != nil {
		t.Fatalf("read exit pubkey: %v", err)
	}

	// 4. Start the geph provider pointing at the exit via the direct constraint
	//    (no broker needed on either side).
	p, err := New(map[string]any{
		"exit_constraint": map[string]any{"direct": fmt.Sprintf("127.0.0.1:%d/%s", c2e, pubHex)},
		"secret":          "test-geph-plugin",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.(*Provider).Close()

	// 5. Wait for the ready flip (listener bound + live session through the
	//    real handshake) and grab the advertised outbound.
	var outbound pub.OutboundConfig
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		outs, err := p.Outbounds(context.Background())
		if err != nil {
			t.Fatalf("Outbounds: %v", err)
		}
		if len(outs) > 0 {
			outbound = outs[0]
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if outbound.ID == "" {
		t.Fatal("provider never became ready (no live session to the exit)")
	}
	t.Logf("provider ready: outbound %s %s %v", outbound.ID, outbound.Protocol, outbound.Config)
	addr, _ := outbound.Config["address"].(string)
	if addr == "" {
		t.Fatalf("outbound has no address: %v", outbound.Config)
	}

	// 6. Push a real HTTP request through the client's SOCKS5 listener — this
	//    exercises the full tunnel: SOCKS5 CONNECT → session OpenConn →
	//    picomux stream + RichTunnelCommand → encrypted records → exit →
	//    target. The CONNECT target is sent as an ATYP=3 domain so the
	//    IPv4-mapped literal survives to the exit's resolver.
	body := httpGetViaSocks5(t, addr, mappedV4Loopback, int(targetPort), "/via-geph", targetAddr)
	if string(body) != "geph-e2e:/via-geph" {
		t.Fatalf("body = %q", string(body))
	}
	t.Logf("small body through tunnel ok (%d bytes)", len(body))

	// 7. A 192 KiB response exercises multi-frame relaying (MSS-sized PSH
	//    frames + MORE flow control) in both directions.
	got := httpGetViaSocks5(t, addr, mappedV4Loopback, int(targetPort), "/big", targetAddr)
	if !bytesEqual(got, bigBody) {
		t.Fatalf("big body mismatch: got %d bytes, want %d", len(got), len(bigBody))
	}
	t.Logf("192KiB body through tunnel ok (%d bytes)", len(got))

	// 8. Optionally also push a request to a real internet host (e.g.
	//    GEPH_TEST_TARGET=223.5.5.5:80) — a fully external round trip. AliDNS
	//    answers GET / with 404, so any well-formed HTTP response counts.
	if realTarget := os.Getenv(envTargetURL); realTarget != "" {
		host, port, err := splitHostPort(realTarget)
		if err != nil {
			t.Fatalf("bad %s: %v", envTargetURL, err)
		}
		var portNum int
		fmt.Sscanf(port, "%d", &portNum)
		body, status := httpGetViaSocks5Status(t, addr, host, portNum, "/", realTarget)
		t.Logf("real-internet body via %s: status %d, %d bytes, starts %q", realTarget, status, len(body), string(body[:min(len(body), 40)]))
		if status < 200 || status >= 600 {
			t.Fatalf("real target %s returned invalid status %d", realTarget, status)
		}
	}
}

// The shared SOCKS5/HTTP helpers this test uses (httpGetViaSocks5,
// bigResponseBody, ...) live in helpers_test.go, which is untagged so the
// standalone embedded-exit test can use them too.

func splitHostPort(hostport string) (string, string, error) {
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[:i], hostport[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("no port in %q", hostport)
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// waitTCP polls until addr accepts a TCP connection.
func waitTCP(t *testing.T, addr string, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s never came up at %s", what, addr)
}

// readExitPubkey derives the exit's ed25519 public key from the signing_secret
// file. The exit's contract: if the file contains exactly 32 bytes it uses
// them as the SigningKey seed (ed25519_dalek SigningKey::from_bytes), else it
// generates a fresh key. The test PRE-CREATES the file with a seed generated
// here, so the public key is derived from the same seed and the direct
// constraint (host:port/pubkeyhex) can pin it. In Go, ed25519.NewKeyFromSeed
// re-derives the same public key from the seed.
func readExitPubkey(secretPath string) (string, error) {
	data, err := os.ReadFile(secretPath)
	if err != nil {
		return "", err
	}
	if len(data) != 32 {
		return "", fmt.Errorf("signing secret file must be exactly 32 bytes, got %d", len(data))
	}
	pubKey := ed25519.NewKeyFromSeed(data).Public().(ed25519.PublicKey)
	return hex.EncodeToString(pubKey), nil
}
