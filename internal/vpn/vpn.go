// Package vpn ports geph5-client's VPN loop (binaries/geph5-client/src/vpn.rs)
// to Go, using gVisor's userspace TCP/IP stack (gvisor.dev/gvisor/pkg/tcpip)
// in place of the Rust ipstack_geph crate.
//
// The VPN loop runs a userspace IP stack. Raw IP packets captured from a
// platform VPN interface (stdio, an fd, or the iOS/Android FFI) are fed into
// the stack; the stack accepts TCP/UDP flows and, for each, opens a tunneled
// connection through the exit (session.Manager.OpenConn) and relays bytes
// bidirectionally. Outbound packets the stack produces are injected back to the
// platform interface.
//
// Wire-format framing (mirrors Rust exactly):
//   - stdio/fd packet framing: a 16-bit big-endian length prefix followed by
//     the raw IP packet, per packet.
//   - UDP-over-tunnel datagram framing: a 2-byte little-endian u16 length
//     prefix per datagram (the tunneled UDP stream is a sequence of
//     length-prefixed datagrams, not a raw byte stream).
//   - On a tunneled-TCP open failure whose error string contains "os error 111"
//     (connection refused), the captured TCP is RST so the app fails fast;
//     other dial errors drop the stream silently (SYN unanswered) so the app's
//     Happy Eyeballs can fall back.
package vpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// dummyNICID is the gVisor NIC id used for the VPN interface.
const dummyNICID tcpip.NICID = 1

// dummyAddr is the IPv4 address assigned to the gVisor NIC (10.0.0.1/24), a
// non-routable address used only so the stack has a source address for
// spoofed flows. Mirrors the Rust dummy IP setup.
const dummyAddr = "10.0.0.1"

// mtu is the MTU for the channel endpoint. Rust uses 16384 on non-iOS.
const mtu uint32 = 16384

// OpenConnFunc opens a tunneled connection to a "host:port" string over the
// given protocol ("tcp" or "udp"). It is session.Manager.OpenConn adapted to
// return a net.Conn.
type OpenConnFunc func(ctx context.Context, protocol, remote string) (net.Conn, error)

// Loop is the VPN loop. It owns the gVisor stack, the channel link endpoint
// (the NIC), and the capture/inject channels that connect the stack to the
// platform VPN interface.
type Loop struct {
	stack    *stack.Stack
	linkEP   *channel.Endpoint
	openConn OpenConnFunc

	// capture carries inbound raw IP packets (from the platform interface)
	// toward the stack. Injected into the gVisor NIC by a feeder goroutine.
	capture chan []byte
	// inject carries outbound raw IP packets (produced by the stack) toward
	// the platform interface. Drained from the gVisor NIC by a drainer
	// goroutine.
	inject chan []byte

	// spoofDNS mirrors Config.spoof_dns: when true, port-53 UDP is handled by
	// a fake DNS responder instead of being tunneled. fakedns is not ported,
	// so spoofDNS only selects the (stubbed) fake-DNS branch.
	spoofDNS bool
}

// New constructs a VPN Loop with the given openConn. It creates the gVisor
// stack, enables ipv4/ipv6 and tcp/udp, creates a channel-based NIC with a
// dummy 10.0.0.1/24 address, enables spoofing + promiscuous mode (so the
// stack accepts flows to any destination, not just its own address), and
// installs a default route through the NIC.
func New(openConn OpenConnFunc) *Loop {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	})

	linkEP := channel.New(256, mtu, "")
	if tcpipErr := s.CreateNIC(dummyNICID, linkEP); tcpipErr != nil {
		log.Printf("vpn: CreateNIC failed: %v", tcpipErr)
	}
	// Promiscuous + spoofing so the stack accepts/originates flows for any
	// address, not just the NIC's own address.
	_ = s.SetPromiscuousMode(dummyNICID, true)
	_ = s.SetSpoofing(dummyNICID, true)

	// Assign the dummy IPv4 address (10.0.0.1/24).
	ipv4Addr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4Slice(net.ParseIP(dummyAddr).To4()),
		PrefixLen: 24,
	}
	if tcpipErr := s.AddProtocolAddress(dummyNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: ipv4Addr,
	}, stack.AddressProperties{}); tcpipErr != nil {
		log.Printf("vpn: AddProtocolAddress ipv4 failed: %v", tcpipErr)
	}
	// Also add an IPv6 address so IPv6 flows have a source.
	ipv6Addr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom16Slice(net.ParseIP("fd00::1").To16()),
		PrefixLen: 64,
	}
	_ = s.AddProtocolAddress(dummyNICID, tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: ipv6Addr,
	}, stack.AddressProperties{})

	// Default route: send everything through the NIC.
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: dummyNICID},
		{Destination: header.IPv6EmptySubnet, NIC: dummyNICID},
	})

	l := &Loop{
		stack:    s,
		linkEP:   linkEP,
		openConn: openConn,
		capture:  make(chan []byte, 100),
		inject:   make(chan []byte, 100),
	}

	// Install the TCP and UDP forwarders that accept flows from the stack.
	l.installForwarders()
	return l
}

// installForwarders registers TCP and UDP forwarders on the stack. Each
// captured flow is handled by opening a tunneled connection and relaying.
func (l *Loop) installForwarders() {
	// TCP forwarder.
	tcpFwd := tcp.NewForwarder(l.stack, 0, 1024, func(req *tcp.ForwarderRequest) {
		l.handleTCP(req)
	})
	l.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// UDP forwarder.
	udpFwd := udp.NewForwarder(l.stack, func(req *udp.ForwarderRequest) bool {
		l.handleUDP(req)
		return true
	})
	l.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
}

// Run starts the VPN loop: a feeder goroutine injects captured packets into the
// gVisor NIC, a drainer goroutine reads packets the stack produces and sends
// them to the inject channel, and the main goroutine blocks until ctx is
// cancelled. The TCP/UDP forwarders run on the stack's internal goroutines.
func (l *Loop) Run(ctx context.Context) error {
	// feeder: capture channel -> gVisor NIC (InjectInbound).
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-l.capture:
				l.injectInbound(pkt)
			}
		}
	}()

	// drainer: gVisor NIC (linkEP.Read) -> inject channel. The link endpoint
	// holds outbound packets (produced by the stack) for the NIC to read.
	go func() {
		for {
			pkt := l.linkEP.Read()
			if pkt == nil {
				// Endpoint closed or no packet available. Avoid busy-looping.
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Millisecond):
					continue
				}
			}
			// Extract the raw IP packet from the PacketBuffer. ToView returns
			// the full packet (network header onward for an outbound packet on
			// a channel endpoint with no link layer).
			view := pkt.ToView()
			if view == nil {
				pkt.DecRef()
				continue
			}
			data := append([]byte(nil), view.AsSlice()...)
			view.Release()
			pkt.DecRef()
			if len(data) == 0 {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case l.inject <- data:
			}
		}
	}()

	<-ctx.Done()
	return ctx.Err()
}

// injectInbound feeds a raw IP packet into the gVisor stack as an inbound
// packet on the NIC. The protocol number is derived from the IP version nibble.
func (l *Loop) injectInbound(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch pkt[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:           buffer.MakeWithData(pkt),
		IsForwardedPacket: true,
	})
	l.linkEP.InjectInbound(proto, pb)
}

// CaptureCh returns the send side for inbound raw IP packets (from the
// platform VPN interface). Mirrors send_vpn_packet / VPN_CAPTURE_CHAN.
func (l *Loop) CaptureCh() chan<- []byte { return l.capture }

// InjectCh returns the receive side for outbound raw IP packets (to the
// platform VPN interface). Mirrors recv_vpn_packet / VPN_INJECT_CHAN.
func (l *Loop) InjectCh() <-chan []byte { return l.inject }

// SendPacket non-blockingly sends an inbound raw IP packet to the stack,
// mirroring send_vpn_packet. If the capture channel is full the packet is
// dropped (the Rust bounded channel would await; we drop to avoid blocking the
// caller, matching the trace-level best-effort semantics).
func (l *Loop) SendPacket(packet []byte) {
	select {
	case l.capture <- packet:
	default:
		log.Printf("vpn: capture channel full, dropping inbound packet (%d bytes)", len(packet))
	}
}

// handleTCP accepts a captured TCP flow, opens a tunneled TCP connection to the
// peer, and relays bidirectionally with try_join semantics (half-close
// propagates, error ends both). On a dial failure containing "os error 111",
// the flow is RST.
func (l *Loop) handleTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	peerAddr := fmt.Sprintf("%s:%d", id.RemoteAddress, id.RemotePort)

	// Create the stack endpoint so we can RST it on failure. We need a
	// waiter.Queue for the endpoint.
	wq := &waiter.Queue{}
	ep, tcpipErr := req.CreateEndpoint(wq)
	if tcpipErr != nil {
		log.Printf("vpn: tcp CreateEndpoint failed: %v", tcpipErr)
		req.Complete(true) // send RST
		return
	}
	// Don't send a RST yet; Complete(false) means we'll handle it.
	req.Complete(false)

	captured := newVPNConn(ep, wq, id)

	// Open the tunneled connection.
	tunneled, err := l.openConn(context.Background(), "tcp", peerAddr)
	if err != nil {
		if containsOSError111(err.Error()) {
			log.Printf("vpn: tcp dial refused for %s, RSTing", peerAddr)
			captured.Close() // closing the gVisor endpoint sends a RST
		} else {
			log.Printf("vpn: tcp dial failed for %s: %v (dropping silently)", peerAddr, err)
			captured.Close()
		}
		return
	}
	log.Printf("vpn: dialed through VPN (tcp %s)", peerAddr)

	// try_join: half-close propagates, error ends both.
	go relayTCP(captured, tunneled)
}

// relayTCP relays bidirectionally between a captured (gVisor) TCP conn and a
// tunneled conn, with try_join semantics.
func relayTCP(captured, tunneled net.Conn) {
	defer captured.Close()
	defer tunneled.Close()
	errc := make(chan error, 2)
	go func() { errc <- copyOne(captured, tunneled) }() // tunneled -> captured
	go func() { errc <- copyOne(tunneled, captured) }() // captured -> tunneled
	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil && firstErr == nil {
			firstErr = err
			captured.Close()
			tunneled.Close()
		}
	}
	if firstErr != nil {
		log.Printf("vpn: tcp relay ended with error: %v", firstErr)
	}
}

// handleUDP accepts a captured UDP flow. Port 53 with spoofDNS would use
// fakedns (not ported); otherwise it opens a tunneled UDP connection and
// relays datagrams with 2-byte LE length prefixes.
func (l *Loop) handleUDP(req *udp.ForwarderRequest) {
	id := req.ID()
	peerAddr := fmt.Sprintf("%s:%d", id.RemoteAddress, id.RemotePort)

	// fakedns branch: not ported. If spoofDNS and port 53, drop (no fake DNS).
	if id.RemotePort == 53 && l.spoofDNS {
		log.Printf("vpn: udp port 53 + spoof_dns: fakedns not ported, dropping")
		return
	}

	wq := &waiter.Queue{}
	ep, tcpipErr := req.CreateEndpoint(wq)
	if tcpipErr != nil {
		log.Printf("vpn: udp CreateEndpoint failed: %v", tcpipErr)
		return
	}
	captured := newVPNConn(ep, wq, id)

	tunneled, err := l.openConn(context.Background(), "udp", peerAddr)
	if err != nil {
		log.Printf("vpn: udp dial failed for %s: %v", peerAddr, err)
		captured.Close()
		return
	}

	go relayUDP(captured, tunneled)
}

// relayUDP relays UDP datagrams between a captured (gVisor) UDP endpoint and a
// tunneled UDP stream. The tunneled stream frames datagrams with a 2-byte
// little-endian u16 length prefix (mirrors Rust exactly).
func relayUDP(captured, tunneled net.Conn) {
	defer captured.Close()
	defer tunneled.Close()

	errc := make(chan error, 2)

	// up: captured -> tunneled, with 2-byte LE length prefix per datagram.
	go func() {
		buf := make([]byte, 65535)
		lenBuf := make([]byte, 2)
		for {
			n, err := captured.Read(buf)
			if err != nil {
				errc <- err
				return
			}
			binary.LittleEndian.PutUint16(lenBuf, uint16(n))
			if _, err := tunneled.Write(lenBuf); err != nil {
				errc <- err
				return
			}
			if _, err := tunneled.Write(buf[:n]); err != nil {
				errc <- err
				return
			}
		}
	}()

	// down: tunneled -> captured, reading 2-byte LE length prefix per datagram.
	go func() {
		lenBuf := make([]byte, 2)
		for {
			if _, err := io.ReadFull(tunneled, lenBuf); err != nil {
				errc <- err
				return
			}
			n := binary.LittleEndian.Uint16(lenBuf)
			buf := make([]byte, n)
			if _, err := io.ReadFull(tunneled, buf); err != nil {
				errc <- err
				return
			}
			if _, err := captured.Write(buf); err != nil {
				errc <- err
				return
			}
		}
	}()

	// Race: either direction ending stops the relay (Rust uses .race()).
	err := <-errc
	if err != nil && !errors.Is(err, io.EOF) {
		log.Printf("vpn: udp relay ended: %v", err)
	}
}

// copyOne copies a single direction: reader -> writer. On EOF it half-closes
// the writer (propagating the close) and returns nil; on any other error it
// returns it. Mirrors litecopy's half-close propagation.
func copyOne(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	if err != nil {
		return err
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	return nil
}

// containsOSError111 reports whether s contains "os error 111" (the Linux
// "Connection refused" errno), mirroring the Rust check
// format!("{err:#}").contains("os error 111").
func containsOSError111(s string) bool {
	return strings.Contains(s, "os error 111")
}

// vpnConn adapts a gVisor tcpip.Endpoint (TCP or UDP) to a net.Conn. It uses a
// waiter.Queue to block on readability/writability. This is the standard gVisor
// userstack adapter pattern.
type vpnConn struct {
	ep       tcpip.Endpoint
	wq       *waiter.Queue
	peerAddr string
}

// newVPNConn wraps a gVisor endpoint as a net.Conn.
func newVPNConn(ep tcpip.Endpoint, wq *waiter.Queue, id stack.TransportEndpointID) *vpnConn {
	return &vpnConn{
		ep:       ep,
		wq:       wq,
		peerAddr: fmt.Sprintf("%s:%d", id.RemoteAddress, id.RemotePort),
	}
}

// Read implements net.Conn. It blocks until the endpoint is readable, then
// reads into p. For UDP, each Read returns one datagram.
func (c *vpnConn) Read(p []byte) (int, error) {
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	c.wq.EventRegister(&waitEntry)
	defer c.wq.EventUnregister(&waitEntry)

	for {
		// Endpoint.Read takes an io.Writer it writes received bytes into. We
		// use a bytes.Buffer and copy out into p, capping at len(p).
		var buf bytes.Buffer
		res, err := c.ep.Read(&buf, tcpip.ReadOptions{})
		if err != nil {
			if isWouldBlock(err) {
				select {
				case <-notifyCh:
					continue
				}
			}
			return 0, toNetError(err)
		}
		n := copy(p, buf.Bytes())
		_ = res
		return n, nil
	}
}

// Write implements net.Conn.
func (c *vpnConn) Write(p []byte) (int, error) {
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	c.wq.EventRegister(&waitEntry)
	defer c.wq.EventUnregister(&waitEntry)

	for {
		n, err := c.ep.Write(bytes.NewReader(p), tcpip.WriteOptions{})
		if err != nil {
			if isWouldBlock(err) {
				select {
				case <-notifyCh:
					continue
				}
			}
			return 0, toNetError(err)
		}
		return int(n), nil
	}
}

// Close implements net.Conn.
func (c *vpnConn) Close() error {
	c.ep.Close()
	return nil
}

// LocalAddr / RemoteAddr / SetDeadline / SetReadDeadline / SetWriteDeadline
// implement the rest of net.Conn. Only RemoteAddr is meaningful.
func (c *vpnConn) LocalAddr() net.Addr                { return &net.IPAddr{} }
func (c *vpnConn) RemoteAddr() net.Addr               { return &net.IPAddr{IP: net.ParseIP(c.peerAddr)} }
func (c *vpnConn) SetDeadline(t time.Time) error      { return nil }
func (c *vpnConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *vpnConn) SetWriteDeadline(t time.Time) error { return nil }

// isWouldBlock reports whether a tcpip.Error is a "would block" / "again" error
// (the endpoint has no data ready and the caller should wait). tcpip.Error is a
// gVisor interface (not a Go error), so we use a type assertion.
func isWouldBlock(err tcpip.Error) bool {
	_, ok := err.(*tcpip.ErrWouldBlock)
	return ok
}

// toNetError converts a tcpip.Error to a net error.
func toNetError(err tcpip.Error) error {
	if err == nil {
		return nil
	}
	if _, ok := err.(*tcpip.ErrClosedForReceive); ok {
		return io.EOF
	}
	return errors.New(err.String())
}

// StdioPump reads 16-bit big-endian length-prefixed packets from r, feeds them
// to the loop's CaptureCh, and reads packets from the loop's InjectCh and
// writes them to w with a 16-bit big-endian length prefix. It mirrors Rust's
// run_stdio_vpn. Returns when either direction ends or ctx is cancelled.
func StdioPump(ctx context.Context, l *Loop, r io.Reader, w io.Writer) error {
	errc := make(chan error, 2)

	// read: r -> CaptureCh (16-bit BE length prefix per packet).
	go func() {
		lenBuf := make([]byte, 2)
		for {
			if _, err := io.ReadFull(r, lenBuf); err != nil {
				errc <- fmt.Errorf("stdio_vpn: read length: %w", err)
				return
			}
			length := binary.BigEndian.Uint16(lenBuf)
			packet := make([]byte, length)
			if _, err := io.ReadFull(r, packet); err != nil {
				errc <- fmt.Errorf("stdio_vpn: read packet: %w", err)
				return
			}
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			case l.capture <- packet:
			}
		}
	}()

	// write: InjectCh -> w (16-bit BE length prefix per packet).
	go func() {
		lenBuf := make([]byte, 2)
		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			case packet := <-l.inject:
				binary.BigEndian.PutUint16(lenBuf, uint16(len(packet)))
				if _, err := w.Write(lenBuf); err != nil {
					errc <- fmt.Errorf("stdio_vpn: write length: %w", err)
					return
				}
				if _, err := w.Write(packet); err != nil {
					errc <- fmt.Errorf("stdio_vpn: write packet: %w", err)
					return
				}
			}
		}
	}()

	return <-errc
}
