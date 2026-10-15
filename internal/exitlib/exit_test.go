// End-to-end test for the embedded exit: a geph5-go client (internal/clientlib)
// tunnels through a geph5-go exit (this package) to a local HTTP target — the
// full client stack and the full exit stack running in ONE process, with no
// Rust binary and no second process:
//
//	HTTP client → SOCKS5 → clientlib (session manager, X25519 handshake,
//	picomux tunnel) → exitlib (conntest, handshake server, tunnel relay) →
//	target HTTP server
package exitlib

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/clientlib"
	"github.com/geph-official/geph5-go/internal/config"
)

// mappedV4Loopback is the IPv4-mapped IPv6 literal for 127.0.0.1. It rides the
// allow rules the same way as against the Rust exit: the client's SOCKS5
// server brackets it into "[::ffff:127.0.0.1]:port", the exit resolves it as
// an IPv6 socket address (no DNS), and the IPv6 routability check — unlike
// the IPv4 one — does not reject the mapped form, while the kernel maps it
// back onto IPv4 loopback when dialing.
const mappedV4Loopback = "::ffff:127.0.0.1"

func TestExitServesClientInOneProcess(t *testing.T) {
	// 1. The "internet": a plain HTTP server on loopback.
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetPort := targetLn.Addr().(*net.TCPAddr).Port
	targetAddr := fmt.Sprintf("127.0.0.1:%d", targetPort)
	bigBody := bigResponseBody(t)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/via-exit":
			fmt.Fprintf(w, "exit-e2e:%s", r.URL.Path)
		case "/big":
			w.Write(bigBody)
		default:
			http.NotFound(w, r)
		}
	})}
	go srv.Serve(targetLn)
	defer srv.Close()

	// 2. The exit (default options: loopback targets rejected, exactly like
	//    the Rust exit's allow rules).
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	exit, err := Start(context.Background(), Options{Seed: seed})
	if err != nil {
		t.Fatal(err)
	}
	defer exit.Close()
	t.Logf("exit serving c2e at %s (pubkey %s)", exit.C2EAddr(), exit.PubkeyHex())

	// 3. The client, pinned at the exit via a direct constraint.
	client, err := clientlib.Start(context.Background(), clientlib.Options{
		Config: &config.Config{
			ExitConstraint: brokerproto.ExitConstraint{
				Kind:   "direct",
				Direct: exit.C2EAddr() + "/" + exit.PubkeyHex(),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	t.Logf("client SOCKS5 at %s", client.SocksAddr())

	waitSessions(t, client, 60*time.Second)

	// 4. Small response through the tunnel (via the mapped-loopback target).
	body := httpGetViaSocks5(t, client.SocksAddr(), mappedV4Loopback, int(targetPort), "/via-exit", targetAddr)
	if string(body) != "exit-e2e:/via-exit" {
		t.Fatalf("body = %q", string(body))
	}
	t.Logf("small body through tunnel ok (%d bytes)", len(body))

	// 5. 192 KiB response: multi-frame picomux relaying in both directions.
	got := httpGetViaSocks5(t, client.SocksAddr(), mappedV4Loopback, int(targetPort), "/big", targetAddr)
	if !bytesEqual(got, bigBody) {
		t.Fatalf("big body mismatch: got %d bytes, want %d", len(got), len(bigBody))
	}
	t.Logf("192KiB body through tunnel ok (%d bytes)", len(got))

	// 6. The allow rules must reject a plain loopback target when
	//    AllowLoopback is off (mirroring the Rust exit's is_globally_routable).
	if _, err := socks5Dial(client.SocksAddr(), "127.0.0.1", int(targetPort)); err == nil {
		t.Fatal("plain loopback target was allowed without AllowLoopback")
	} else {
		t.Logf("plain loopback correctly rejected: %v", err)
	}
}

func TestExitAllowLoopbackOption(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	targetPort := targetLn.Addr().(*net.TCPAddr).Port
	targetAddr := fmt.Sprintf("127.0.0.1:%d", targetPort)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello:%s", r.URL.Path)
	})}
	go srv.Serve(targetLn)
	defer srv.Close()

	exit, err := Start(context.Background(), Options{AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	defer exit.Close()

	client, err := clientlib.Start(context.Background(), clientlib.Options{
		Config: &config.Config{
			ExitConstraint: brokerproto.ExitConstraint{
				Kind:   "direct",
				Direct: exit.C2EAddr() + "/" + exit.PubkeyHex(),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	waitSessions(t, client, 60*time.Second)

	body := httpGetViaSocks5(t, client.SocksAddr(), "127.0.0.1", int(targetPort), "/x", targetAddr)
	if string(body) != "hello:/x" {
		t.Fatalf("body = %q", string(body))
	}
}

// waitSessions polls until the client reports a live session.
func waitSessions(t *testing.T, client *clientlib.Client, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if client.SessionCount() > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no live session within " + timeout.String())
}

// httpGetViaSocks5 dials a SOCKS5 CONNECT through the proxy at proxyAddr for
// host:port (host sent as an ATYP=3 domain so IPv6 literals survive
// un-normalized), then issues an HTTP/1.1 GET and returns the body.
func httpGetViaSocks5(t *testing.T, proxyAddr, host string, port int, path, hostHeader string) []byte {
	t.Helper()
	conn, err := socks5Dial(proxyAddr, host, port)
	if err != nil {
		t.Fatalf("socks5 connect: %v", err)
	}
	defer conn.Close()
	req, err := http.NewRequest(http.MethodGet, "http://"+hostHeader+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(conn); err != nil {
		t.Fatalf("write http request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read http response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	return body
}

// socks5Dial performs a SOCKS5 CONNECT to host:port through proxyAddr, sending
// the host as an ATYP=3 domain name.
func socks5Dial(proxyAddr, host string, port int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		conn.Close()
		return nil, err
	}
	if sel[0] != 0x05 || sel[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: method selection reply %v", sel)
	}
	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: reply head: %w", err)
	}
	if head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: reply status %d", head[1])
	}
	addrLen := 0
	switch head[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: reply addr len: %w", err)
		}
		addrLen = int(n[0])
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: reply atyp %d", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, addrLen+2)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: reply addr/port: %w", err)
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// bigResponseBody builds a deterministic 192 KiB pattern (larger than the
// picomux MSS so it spans many PSH frames).
func bigResponseBody(t *testing.T) []byte {
	t.Helper()
	const size = 192 * 1024
	b := make([]byte, size)
	for i := range b {
		b[i] = byte((i*7 + 13) % 251)
	}
	return b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
