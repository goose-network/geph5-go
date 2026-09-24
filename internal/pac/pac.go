// Package pac implements a PAC (Proxy Auto-Configuration) file server, a port
// of binaries/geph5-client/src/pac.rs.
//
// It binds an HTTP/1.1 listener and, for every request, responds with a PAC
// script of the form:
//
//	function FindProxyForURL(url, host){return '<DIRECTIVE>';}
//
// where DIRECTIVE is chosen to point local browsers at the loopback address of
// the configured HTTP proxy (preferred) or SOCKS5 proxy, falling back to
// "DIRECT" when neither is configured. A wildcard (unspecified) bind address
// is rewritten to 127.0.0.1 because the PAC is consumed by local browsers,
// which cannot dial 0.0.0.0.
package pac

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
)

// Serve binds a PAC HTTP server to listen and serves PAC responses until ctx
// is canceled. socks5Listen and httpProxyListen are the listen addresses of
// the corresponding proxies; an empty value means that proxy is not
// configured. If listen is empty, Serve blocks forever (matching Rust's
// pac_serve when pac_listen is None, which awaits std::future::pending).
func Serve(ctx context.Context, listen, socks5Listen, httpProxyListen string) error {
	if listen == "" {
		<-ctx.Done()
		return ctx.Err()
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("pac: listen %s: %w", listen, err)
	}
	log.Printf("pac: listening on %s", listen)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directive := pickDirective(socks5Listen, httpProxyListen)
		body := fmt.Sprintf("function FindProxyForURL(url, host){return '%s';}", directive)
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})

	srv := &http.Server{Handler: handler}
	// When ctx is canceled the listener is closed, causing Serve to return.
	if err := srv.Serve(ln); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("pac: serve %s: %w", listen, err)
	}
	return nil
}

// pickDirective mirrors the directive-selection logic in pac.rs: prefer the
// HTTP proxy, fall back to SOCKS5 (with a legacy SOCKS fallback), and
// otherwise return "DIRECT".
func pickDirective(socks5Listen, httpProxyListen string) string {
	if httpProxyListen != "" {
		return "PROXY " + toLoopback(httpProxyListen)
	}
	if socks5Listen != "" {
		socks := toLoopback(socks5Listen)
		return "SOCKS5 " + socks + "; SOCKS " + socks
	}
	return "DIRECT"
}

// toLoopback rewrites a wildcard (unspecified) bind address to 127.0.0.1,
// matching the to_loopback closure in pac.rs. Addresses that already bind a
// concrete IP are returned unchanged.
func toLoopback(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		// Not host:port; return as-is rather than guessing.
		return listen
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}
