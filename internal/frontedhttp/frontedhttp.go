// Package frontedhttp implements the domain-fronted HTTP transport for
// broker RPC, matching geph5-client's FrontedHttpTransport.
//
// The transport POSTs the JSON-RPC body to a front URL (e.g.
// https://kubernetes.io/) with:
//   - Host header set to the real broker host (domain fronting)
//   - X-Padding header with random base64 noise (7..375 bytes)
//   - Content-Type: application/json
//
// The TLS SNI uses the front's hostname (the URL host), while the inner HTTP
// Host header carries the real broker host. The response body is the
// JSON-RPC response.
package frontedhttp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/geph-official/geph5-go/internal/nanorpc"
)

// Transport is a fronted-HTTP nanorpc transport.
type Transport struct {
	FrontURL string // e.g. https://kubernetes.io/
	Host     string // real broker host (Host header); empty = no fronting
	OverrideDNS []string // "ip:port" to pin DNS resolution of the front; empty = system DNS
	client  *http.Client
}

// New creates a Transport. A shared http.Client is built per transport so
// that OverrideDNS can be applied via a custom Dialer.
func New(frontURL, host string, overrideDNS []string) (*Transport, error) {
	t := &Transport{FrontURL: frontURL, Host: host, OverrideDNS: overrideDNS}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	transport := &http.Transport{
		Proxy:           nil, // no_proxy equivalent
		ForceAttemptHTTP2: true,
	}
	if len(overrideDNS) > 0 {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Pin to the override address, preserving the port from addr if the
			// override has no port.
			target := overrideDNS[0]
			_, _, err := net.SplitHostPort(target)
			if err != nil {
				// override has no port; use the port from the resolved addr.
				_, port, _ := net.SplitHostPort(addr)
				target = net.JoinHostPort(target, port)
			}
			return dialer.DialContext(ctx, network, target)
		}
	} else {
		transport.DialContext = dialer.DialContext
	}
	t.client = &http.Client{Transport: transport, Timeout: 60 * time.Second}
	return t, nil
}

// CallRaw implements nanorpc.RpcTransport.
func (t *Transport) CallRaw(ctx context.Context, req *nanorpc.JrpcRequest) (*nanorpc.JrpcResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("frontedhttp: marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", t.FrontURL, bytesReader(body))
	if err != nil {
		return nil, fmt.Errorf("frontedhttp: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if t.Host != "" {
		httpReq.Header.Set("Host", t.Host)
		httpReq.Header.Set("X-Padding", randomPadding())
	}
	// Ensure TLS SNI uses the front URL's host. Go's default TLS client sets
	// SNI from the URL host automatically, so domain fronting works: SNI =
	// front host, inner Host header = real broker host.
	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("frontedhttp: send: %w", err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("frontedhttp: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("frontedhttp: front returned HTTP %d: %s", resp.StatusCode, string(respBytes))
	}
	var jrpcResp nanorpc.JrpcResponse
	if err := json.Unmarshal(respBytes, &jrpcResp); err != nil {
		return nil, fmt.Errorf("frontedhttp: decode response: %w (body: %s)", err, string(respBytes))
	}
	return &jrpcResp, nil
}

// randomPadding returns a base64-no-pad encoding of 7..375 random bytes,
// matching geph5's X-Padding header.
func randomPadding() string {
	n, err := rand.Int(rand.Reader, big.NewInt(369)) // 0..368
	if err != nil {
		return ""
	}
	size := int(n.Int64()) + 7 // 7..375
	b := make([]byte, size)
	_, _ = rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b)
}

// bytesReader returns a reader for b without pulling in bytes.NewReader import noise.
func bytesReader(b []byte) io.Reader { return &byteReader{b: b} }

type byteReader struct {
	b []byte
	i int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

// FrontHost returns the host portion of the front URL (for diagnostics).
func (t *Transport) FrontHost() string {
	u, err := url.Parse(t.FrontURL)
	if err != nil {
		return ""
	}
	return u.Host
}
