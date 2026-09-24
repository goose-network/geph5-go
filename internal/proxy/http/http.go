// Package http implements a minimal HTTP proxy server, a port of the
// connect/forward paths of binaries/geph5-client/src/http_proxy/mod.rs.
//
// It supports:
//   - HTTP CONNECT: upgrades the connection to a bidirectional TCP tunnel
//     through the geph5 exit (via the openConn callback).
//   - Plain HTTP (GET/POST/...) forwarding: dials the target host through the
//     tunnel and relays the raw request bytes and response.
//
// Hop-by-hop header stripping and keep-alive handling follow the Rust
// implementation. HTTPS via CONNECT is the primary use case; plain HTTP
// forwarding is included for completeness.
package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/geph-official/geph5-go/internal/session"
)

// Serve binds an HTTP proxy listener to listenAddr and serves connections
// until ctx is canceled. openConn tunnels TCP connections through the geph5
// exit. If listenAddr is empty, Serve blocks forever (matching Rust's
// http_proxy_serve when no listen address is configured).
func Serve(ctx context.Context, listenAddr string, openConn session.OpenConnFunc) error {
	if listenAddr == "" {
		<-ctx.Done()
		return ctx.Err()
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("http: listen %s: %w", listenAddr, err)
	}
	log.Printf("http: listening on %s", listenAddr)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("http: accept failed: %v", err)
			continue
		}
		go handleConn(ctx, conn, openConn)
	}
}

// handleConn serves a single HTTP proxy connection.
func handleConn(ctx context.Context, client net.Conn, openConn session.OpenConnFunc) {
	defer client.Close()
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		if err != io.EOF {
			log.Printf("http: read request from %s failed: %v", client.RemoteAddr(), err)
		}
		return
	}
	if req.Method == http.MethodConnect {
		handleConnect(ctx, client, req, openConn)
		return
	}
	handleForward(ctx, client, br, req, openConn)
}

// handleConnect implements the CONNECT tunnel: dials the target through the
// tunnel and relays bytes bidirectionally.
func handleConnect(ctx context.Context, client net.Conn, req *http.Request, openConn session.OpenConnFunc) {
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	remote, err := openConn(ctx, target)
	if err != nil {
		log.Printf("http: CONNECT %s open_conn failed: %v", target, err)
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer remote.Close()
	if _, err := fmt.Fprintf(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("http: CONNECT %s write reply failed: %v", target, err)
		return
	}
	// Bidirectional relay.
	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, client); done <- struct{}{} }()
	go func() { io.Copy(client, remote); done <- struct{}{} }()
	<-done
}

// handleForward forwards a plain HTTP request to the target through the
// tunnel and relays the response. The request is rewritten so the
// Request-URI is the path only (the full absolute URI form is converted to
// origin-form before forwarding, per HTTP proxy conventions).
func handleForward(ctx context.Context, client net.Conn, br *bufio.Reader, req *http.Request, openConn session.OpenConnFunc) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		writeStatus(client, http.StatusBadRequest, "bad request: no host")
		return
	}
	// Default port.
	if !hasPort(host) {
		if req.URL.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}
	remote, err := openConn(ctx, host)
	if err != nil {
		log.Printf("http: forward %s open_conn failed: %v", host, err)
		writeStatus(client, http.StatusBadGateway, "relay failed: "+err.Error())
		return
	}
	defer remote.Close()
	// Strip hop-by-hop headers and rewrite the request URI to origin form.
	clearHopHeaders(req.Header)
	if req.URL.Scheme != "" {
		// Convert absolute-URI form to origin-form (path?query).
		req.RequestURI = req.URL.RequestURI()
	}
	if err := req.Write(remote); err != nil {
		log.Printf("http: forward %s write request failed: %v", host, err)
		return
	}
	// Flush any buffered request body from the bufio reader.
	if br.Buffered() > 0 {
		if _, err := io.Copy(remote, br); err != nil {
			log.Printf("http: forward %s flush body failed: %v", host, err)
			return
		}
	}
	// Relay the response back to the client.
	resp, err := http.ReadResponse(bufio.NewReader(remote), req)
	if err != nil {
		log.Printf("http: forward %s read response failed: %v", host, err)
		writeStatus(client, http.StatusBadGateway, "relay failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	clearHopHeaders(resp.Header)
	if err := resp.Write(client); err != nil {
		log.Printf("http: forward %s write response failed: %v", host, err)
		return
	}
}

// writeStatus writes a simple HTTP status line and body to the client.
func writeStatus(client net.Conn, code int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
	_, _ = client.Write([]byte(resp))
}

// hasPort reports whether host already contains a port.
func hasPort(host string) bool {
	if strings.HasPrefix(host, "[") {
		return strings.Contains(host, "]:")
	}
	return strings.Count(host, ":") == 1
}

// clearHopHeaders removes hop-by-hop headers per RFC 7230, matching the Rust
// clear_hop_headers.
func clearHopHeaders(h http.Header) {
	for _, name := range []string{
		"Keep-Alive",
		"Transfer-Encoding",
		"Te",
		"Connection",
		"Trailer",
		"Upgrade",
		"Proxy-Authorization",
		"Proxy-Authenticate",
		"Proxy-Connection",
	} {
		h.Del(name)
	}
}
