// helpers_test.go holds the SOCKS5/HTTP test helpers shared by the plugin's
// test variants (the geph_real real-network test and the standalone
// embedded-exit test). It is untagged so the standalone tests run in the
// default `go test ./...`.
package geph

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// httpGetViaSocks5 dials a SOCKS5 CONNECT through the proxy at proxyAddr for
// host:port (host sent as a domain literal), then issues an HTTP/1.1 GET for
// path and returns the full response body. hostHeader sets the Host header.
// It requires a 200 response; see httpGetViaSocks5Status for the
// status-tolerant variant used against real internet targets (whose status
// is whatever the real server answers, e.g. AliDNS's 404 for "/").
func httpGetViaSocks5(t *testing.T, proxyAddr, host string, port int, path, hostHeader string) []byte {
	t.Helper()
	body, status := httpGetViaSocks5Status(t, proxyAddr, host, port, path, hostHeader)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	return body
}

// httpGetViaSocks5Status is httpGetViaSocks5 without the status assertion: it
// returns the response body and status code.
func httpGetViaSocks5Status(t *testing.T, proxyAddr, host string, port int, path, hostHeader string) ([]byte, int) {
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
	return body, resp.StatusCode
}

// socks5Dial performs a SOCKS5 CONNECT to host:port through the proxy at
// proxyAddr, sending the host as an ATYP=3 domain name so the literal string
// reaches the tunnel un-normalized (an IPv4 ATYP would make the client render
// ::ffff:127.0.0.1 as plain 127.0.0.1, which the exit refuses to proxy to).
func socks5Dial(proxyAddr, host string, port int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	// Greeting: VER=5, one method, no-auth.
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
	// CONNECT request with ATYP=3 domain.
	if len(host) > 255 {
		conn.Close()
		return nil, fmt.Errorf("socks5: host too long")
	}
	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	// Reply: VER REP RSV ATYP, then BND.ADDR, then BND.PORT.
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
