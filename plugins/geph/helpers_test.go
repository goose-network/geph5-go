// helpers_test.go holds the HTTP-over-outbound test helpers shared by the
// plugin's test variants (the geph_real real-network test and the standalone
// embedded-exit test). It is untagged so the standalone tests run in the
// default `go test ./...`.
package geph

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	pub "github.com/goose-network/goose-plugin-api"
)

// httpGetViaOutbound dials host:port through the "geph" outbound — the same
// in-process call the engine's router makes — then issues an HTTP/1.1 GET for
// path and returns the full response body. hostHeader sets the Host header.
// It requires a 200 response; see httpGetViaOutboundStatus for the
// status-tolerant variant used against real internet targets (whose status is
// whatever the real server answers, e.g. AliDNS's 404 for "/").
func httpGetViaOutbound(t *testing.T, ob pub.Outbound, host string, port int, path, hostHeader string) []byte {
	t.Helper()
	body, status := httpGetViaOutboundStatus(t, ob, host, port, path, hostHeader)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	return body
}

// httpGetViaOutboundStatus is httpGetViaOutbound without the status
// assertion: it returns the response body and status code.
func httpGetViaOutboundStatus(t *testing.T, ob pub.Outbound, host string, port int, path, hostHeader string) ([]byte, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	remote := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := ob.DialContext(ctx, pub.NetworkTCP, remote)
	if err != nil {
		t.Fatalf("outbound dial %s: %v", remote, err)
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
