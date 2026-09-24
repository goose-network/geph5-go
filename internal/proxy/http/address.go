// Package http implements an HTTP/1.1 proxy server that tunnels all
// outbound traffic through a caller-supplied openConn function (the geph5
// tunnel), mirroring geph5-client's http_proxy module.
//
// The Address type and the host_addr/authority_addr helpers are ports of
// http_proxy/address.rs. CONNECT requests are relayed as a raw TCP pipe;
// ordinary HTTP requests are forwarded through an http.Transport whose
// DialContext dials the target via openConn, so no traffic ever goes direct.
package http

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Address mirrors the Rust enum address::Address:
//
//	SocketAddress(SocketAddr)
//	DomainNameAddress(String, u16)
type Address struct {
	// Kind is "socket" or "domain".
	Kind string
	// IP is set when Kind == "socket".
	IP net.IP
	// Port is the port for both variants.
	Port uint16
	// Domain is set when Kind == "domain".
	Domain string
}

// Address kinds.
const (
	KindSocket = "socket"
	KindDomain = "domain"
)

// String mirrors Address's Display impl:
//
//	SocketAddress -> "{ip}:{port}"
//	DomainNameAddress -> "{domain}:{port}"
func (a Address) String() string {
	switch a.Kind {
	case KindSocket:
		if a.IP.To4() != nil {
			return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
		}
		return fmt.Sprintf("[%s]:%d", a.IP.String(), a.Port)
	case KindDomain:
		return fmt.Sprintf("%s:%d", a.Domain, a.Port)
	}
	return ""
}

// fromSocketAddr builds an Address from a net.Addr whose String() is an
// ip:port pair (e.g. a *net.TCPAddr). Currently unused but kept for parity
// with the Rust From<SocketAddr> impl.
func fromSocketAddr(s net.Addr) Address {
	if tcp, ok := s.(*net.TCPAddr); ok {
		return Address{Kind: KindSocket, IP: tcp.IP, Port: uint16(tcp.Port)}
	}
	// Fall back to parsing the string form.
	host, portStr, err := net.SplitHostPort(s.String())
	if err != nil {
		return Address{Kind: KindDomain, Domain: s.String(), Port: 0}
	}
	port, _ := strconv.ParseUint(portStr, 10, 16)
	ip := net.ParseIP(host)
	if ip != nil {
		return Address{Kind: KindSocket, IP: ip, Port: uint16(port)}
	}
	return Address{Kind: KindDomain, Domain: host, Port: uint16(port)}
}

// hostAddr mirrors address::host_addr: extract an Address from a URI's
// authority, applying default ports (80 for http, 443 for https) when none
// is present. Returns nil when the authority is absent or invalid.
func hostAddr(u *url.URL) *Address {
	if u == nil {
		return nil
	}
	host := u.Host
	if host == "" {
		return nil
	}
	// authority may include userinfo (user:pass@host); strip it.
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	if host == "" {
		return nil
	}

	if _, portStr, err := net.SplitHostPort(host); err == nil {
		// Has an explicit port.
		port, perr := strconv.ParseUint(portStr, 10, 16)
		if perr != nil {
			return nil
		}
		// Maybe it's a literal SocketAddr (127.0.0.1:1234, [::1]:1234).
		// If the host part is an IP, treat as a socket address; otherwise
		// it's a domain name with an explicit port.
		hostname := hostOnly(host)
		if ip := net.ParseIP(hostname); ip != nil {
			return &Address{Kind: KindSocket, IP: ip, Port: uint16(port)}
		}
		return &Address{Kind: KindDomain, Domain: hostname, Port: uint16(port)}
	}

	// No port: use default from scheme.
	var port uint16
	switch u.Scheme {
	case "", "http":
		port = 80
	case "https":
		port = 443
	default:
		return nil
	}

	// IPv6 wrapped in [ ].
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		addr := host[1 : len(host)-1]
		if ip := net.ParseIP(addr); ip != nil {
			return &Address{Kind: KindSocket, IP: ip, Port: port}
		}
		return nil
	}
	// IPv4 or domain.
	if ip := net.ParseIP(host); ip != nil {
		return &Address{Kind: KindSocket, IP: ip, Port: port}
	}
	return &Address{Kind: KindDomain, Domain: host, Port: port}
}

// hostOnly returns the host part of a host:port string, preserving IPv6
// brackets so net.ParseIP can still parse them.
func hostOnly(hostport string) string {
	if strings.HasPrefix(hostport, "[") {
		if i := strings.LastIndex(hostport, "]"); i >= 0 {
			return hostport[:i+1]
		}
	}
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		return hostport[:i]
	}
	return hostport
}

// authorityAddr mirrors address::authority_addr: given a scheme and an
// authority string (host[:port], optionally with userinfo), return an
// Address with the default port applied when missing. Returns nil for
// unsupported schemes or invalid bracketed IPv6.
func authorityAddr(scheme, authority string) *Address {
	// Strip userinfo.
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		authority = authority[i+1:]
	}
	if authority == "" {
		return nil
	}

	host := authority
	portStr := ""
	if h, p, err := net.SplitHostPort(authority); err == nil {
		host, portStr = h, p
	}

	var port uint16
	if portStr != "" {
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil
		}
		port = uint16(p)
	} else {
		switch scheme {
		case "", "http":
			port = 80
		case "https":
			port = 443
		default:
			return nil
		}
	}

	// Bracketed IPv6.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		addr := host[1 : len(host)-1]
		if ip := net.ParseIP(addr); ip != nil {
			return &Address{Kind: KindSocket, IP: ip, Port: port}
		}
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return &Address{Kind: KindSocket, IP: ip, Port: port}
	}
	return &Address{Kind: KindDomain, Domain: host, Port: port}
}
