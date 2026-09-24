// Package socks5 implements a minimal SOCKS5 proxy server, a port of the
// connect-handling path of binaries/geph5-client/src/socks5.rs.
//
// It supports the no-authentication method and the CONNECT command (TCP
// relay). UDP ASSOCIATE and BIND are not supported (the Rust client's UDP
// path depends on the full session/litecopy machinery). Each accepted
// connection is handled in its own goroutine: the SOCKS5 handshake is read,
// the target is dialed through the provided openConn callback (which tunnels
// through the geph5 exit), and the two directions are copied bidirectionally
// until one side closes.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"

	"github.com/geph-official/geph5-go/internal/session"
)

// Serve binds a SOCKS5 listener to listenAddr and serves connections until
// ctx is canceled. openConn is used to establish the tunneled TCP connection
// to the requested target. If listenAddr is empty, Serve blocks forever
// (matching Rust's http_proxy_serve when no listen address is configured).
func Serve(ctx context.Context, listenAddr string, openConn session.OpenConnFunc) error {
	if listenAddr == "" {
		<-ctx.Done()
		return ctx.Err()
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("socks5: listen %s: %w", listenAddr, err)
	}
	log.Printf("socks5: listening on %s", listenAddr)
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
			log.Printf("socks5: accept failed: %v", err)
			continue
		}
		go handleConn(ctx, conn, openConn)
	}
}

// handleConn performs the SOCKS5 handshake and relays the connection.
func handleConn(ctx context.Context, client net.Conn, openConn session.OpenConnFunc) {
	defer client.Close()
	host, port, err := handshake(client)
	if err != nil {
		log.Printf("socks5: handshake from %s failed: %v", client.RemoteAddr(), err)
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	remote, err := openConn(ctx, target)
	if err != nil {
		log.Printf("socks5: open_conn to %s failed: %v", target, err)
		// Reply with a generic failure (0x01).
		writeReply(client, 0x01, net.IPv4zero, 0)
		return
	}
	defer remote.Close()
	// Success reply: bound address is 0.0.0.0:0 (the client ignores it).
	if err := writeReply(client, 0x00, net.IPv4zero, 0); err != nil {
		log.Printf("socks5: write reply failed: %v", err)
		return
	}
	// Bidirectional copy. A half-close in one direction must not drop the
	// other, so we run both copies and wait for both to finish.
	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, client); done <- struct{}{} }()
	go func() { io.Copy(client, remote); done <- struct{}{} }()
	<-done
}

// handshake reads the SOCKS5 greeting and request, returning the target host
// and port. It writes the no-auth method selection and expects a CONNECT
// command.
func handshake(client net.Conn) (host string, port uint16, err error) {
	// Greeting: VER, NMETHODS, METHODS...
	buf := make([]byte, 2)
	if _, err := io.ReadFull(client, buf); err != nil {
		return "", 0, fmt.Errorf("read greeting: %w", err)
	}
	if buf[0] != 0x05 {
		return "", 0, errors.New("socks5: not SOCKS5")
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(client, make([]byte, nMethods)); err != nil {
		return "", 0, fmt.Errorf("read methods: %w", err)
	}
	// Select no-auth (0x00).
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return "", 0, fmt.Errorf("write method: %w", err)
	}
	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	if _, err := io.ReadFull(client, buf[:3]); err != nil {
		return "", 0, fmt.Errorf("read request header: %w", err)
	}
	if buf[0] != 0x05 {
		return "", 0, errors.New("socks5: bad request version")
	}
	if buf[1] != 0x01 { // only CONNECT
		return "", 0, errors.New("socks5: only CONNECT supported")
	}
	// buf[2] is RSV (reserved, must be 0x00). Read ATYP next.
	if _, err := io.ReadFull(client, buf[:1]); err != nil {
		return "", 0, fmt.Errorf("read atyp: %w", err)
	}
	atyp := buf[0]
	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(client, ip); err != nil {
			return "", 0, fmt.Errorf("read ipv4: %w", err)
		}
		host = net.IP(ip).String()
	case 0x03: // domain
		if _, err := io.ReadFull(client, buf[:1]); err != nil {
			return "", 0, fmt.Errorf("read domain len: %w", err)
		}
		domain := make([]byte, int(buf[0]))
		if _, err := io.ReadFull(client, domain); err != nil {
			return "", 0, fmt.Errorf("read domain: %w", err)
		}
		host = string(domain)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(client, ip); err != nil {
			return "", 0, fmt.Errorf("read ipv6: %w", err)
		}
		host = net.IP(ip).String()
	default:
		return "", 0, fmt.Errorf("socks5: unsupported atyp %d", atyp)
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(client, portBuf[:]); err != nil {
		return "", 0, fmt.Errorf("read port: %w", err)
	}
	port = binary.BigEndian.Uint16(portBuf[:])
	return host, port, nil
}

// writeReply writes a SOCKS5 reply with the given status, bound address, and
// port.
func writeReply(client net.Conn, status byte, ip net.IP, port uint16) error {
	var atyp byte
	var addr []byte
	if ip4 := ip.To4(); ip4 != nil {
		atyp = 0x01
		addr = ip4
	} else {
		atyp = 0x04
		addr = ip.To16()
	}
	reply := make([]byte, 0, 4+len(addr)+2)
	reply = append(reply, 0x05, status, 0x00, atyp)
	reply = append(reply, addr...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)
	reply = append(reply, portBuf[:]...)
	_, err := client.Write(reply)
	return err
}
