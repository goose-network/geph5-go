// This file implements the meeklike transport's datagram connection
// (DgConnection), dialer (MeeklikeDialer), and pipe (MeeklikePipe), porting
// sillad-meeklike's lib.rs and datagram.rs.
//
// DgConnection is an unreliable datagram channel backed by HTTP POST
// request/response pairs. The client POSTs an encrypted Datagram as the body
// to "/" and receives an encrypted Datagram as the response body. Up to
// max_inflight POSTs run concurrently.
//
// MeeklikeDialer wraps an inner sillad.Dialer (which provides the HTTP
// transport's TCP/TLS connection) and produces a MeeklikePipe. The pipe is a
// virta reliable Stream carried over the DgConnection's datagrams.
package meeklike

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/geph-official/geph5-go/internal/blake3"
	"github.com/geph-official/geph5-go/internal/sillad"
)

// Config mirrors sillad_meeklike::MeeklikeConfig.
type Config struct {
	MaxInflight int  `json:"max_inflight"`
	Mss         int  `json:"mss"`
	Base64      bool `json:"base64"`
}

// DefaultConfig returns the Rust Default for MeeklikeConfig.
func DefaultConfig() Config {
	return Config{MaxInflight: 50, Mss: 3000, Base64: false}
}

// withDefaults returns a Config with zero fields replaced by defaults.
func (c Config) withDefaults() Config {
	out := c
	if out.MaxInflight <= 0 {
		out.MaxInflight = 50
	}
	if out.Mss <= 0 {
		out.Mss = 3000
	}
	return out
}

// DgConnection is an unreliable datagram connection backed by HTTP POST. The
// client sends datagrams via Send (non-blocking) and receives them via Recv
// (blocking). It mirrors sillad_meeklike::datagram::DgConnection.
type DgConnection struct {
	sendCh chan []byte // datagrams to send (upstream)
	recvCh chan []byte // datagrams received (downstream)

	closeOnce sync.Once
	closed    chan struct{}
}

// newDgConnection starts the HTTP POST backhaul. inner is the dialer that
// yields the underlying HTTP transport connection (e.g. a TCP or TLS sillad
// Pipe). cfg.max_inflight goroutines run the request/response loop.
func newDgConnection(ctx context.Context, cfg Config, secret *PresharedSecret, streamID StreamID, inner sillad.Dialer) *DgConnection {
	cfg = cfg.withDefaults()
	d := &DgConnection{
		sendCh: make(chan []byte, 1000),
		recvCh: make(chan []byte, 1000),
		closed: make(chan struct{}),
	}
	for i := 0; i < cfg.MaxInflight; i++ {
		go d.backhaulLoop(ctx, cfg, secret, streamID, inner)
	}
	return d
}

// Send enqueues a datagram for upstream transmission. It never blocks (drops
// if the send buffer is full), matching Rust's try_send.
func (d *DgConnection) Send(b []byte) {
	select {
	case d.sendCh <- b:
	default:
	}
}

// Recv blocks until a downstream datagram is available or the connection is
// closed.
func (d *DgConnection) Recv() ([]byte, error) {
	select {
	case b := <-d.recvCh:
		return b, nil
	case <-d.closed:
		return nil, errDgClosed
	}
}

// Close shuts down the backhaul goroutines.
func (d *DgConnection) Close() {
	d.closeOnce.Do(func() { close(d.closed) })
}

var errDgClosed = errors.New("meeklike: datagram connection closed")

// backhaulLoop runs one inflight slot of the HTTP POST request/response loop,
// mirroring dg_client_backhaul. It polls the send channel with a small timeout
// (so empty datagrams are sent as keepalives), POSTs the encrypted datagram,
// and forwards any response inner bytes to recvCh.
func (d *DgConnection) backhaulLoop(ctx context.Context, cfg Config, secret *PresharedSecret, streamID StreamID, inner sillad.Dialer) {
	interval := 0.02
	for {
		select {
		case <-d.closed:
			return
		case <-ctx.Done():
			return
		default:
		}

		var toSend []byte
		timer := time.NewTimer(time.Duration(interval * float64(time.Second)))
		select {
		case b := <-d.sendCh:
			toSend = b
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			toSend = nil // empty keepalive
		case <-d.closed:
			return
		case <-ctx.Done():
			return
		}

		// Build the encrypted Datagram.
		dg := &Datagram{
			Ts:       uint64(time.Now().Unix()),
			StreamID: streamID,
			Inner:    toSend,
		}
		plain, err := dg.MarshalStdcode()
		if err != nil {
			continue
		}
		ct := secret.EncryptUp(plain)
		var body []byte
		if cfg.Base64 {
			body = []byte(base64.StdEncoding.EncodeToString(ct))
		} else {
			body = ct
		}

		// POST with a 10s overall timeout.
		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		respBytes, err := d.doPost(reqCtx, inner, body)
		cancel()
		if err != nil {
			// On error, back off (increase interval), matching Rust.
			if len(toSend) == 0 {
				interval = interval * 2
				if interval > 30 {
					interval = 30
				}
			}
			continue
		}

		var raw []byte
		if cfg.Base64 {
			dec, err := base64.StdEncoding.DecodeString(string(respBytes))
			if err != nil {
				continue
			}
			raw = dec
		} else {
			raw = respBytes
		}
		plain, err = secret.DecryptDn(raw)
		if err != nil {
			continue
		}
		var resp Datagram
		if err := resp.UnmarshalStdcode(plain); err != nil {
			continue
		}
		if !resp.StreamID.Equal(streamID) {
			continue
		}
		if len(resp.Inner) > 0 {
			select {
			case d.recvCh <- resp.Inner:
				interval = 0.1
			default:
			}
		} else {
			// empty response: increase interval
			interval = interval * 2
			if interval > 30 {
				interval = 30
			}
		}
	}
}

// doPost dials the inner dialer, builds an HTTP/1.1 POST to "/" over the raw
// sillad.Pipe, and returns the response body. The Rust code uses hyper's
// client::conn::http1::handshake over the dialed connection; we do a minimal
// HTTP/1.1 request by hand over the Pipe (which is a net.Conn).
func (d *DgConnection) doPost(ctx context.Context, inner sillad.Dialer, body []byte) ([]byte, error) {
	pipe, err := inner.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("meeklike: dial inner: %w", err)
	}
	defer pipe.Close()

	// Write a minimal HTTP/1.1 POST request.
	req := buildHTTPRequest("/", body)
	if _, err := pipe.Write(req); err != nil {
		return nil, fmt.Errorf("meeklike: write request: %w", err)
	}

	// Read the response. We parse the HTTP/1.1 response: status line, headers,
	// then a body delimited by Content-Length or by connection close.
	return readHTTPResponse(pipe)
}

// buildHTTPRequest builds a minimal HTTP/1.1 POST request with a Content-Length
// body. The Host header is left empty (the inner transport's SNI/Host is set
// elsewhere if needed).
func buildHTTPRequest(path string, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("POST ")
	b.WriteString(path)
	b.WriteString(" HTTP/1.1\r\n")
	b.WriteString("Host: localhost\r\n")
	b.WriteString("Content-Type: application/octet-stream\r\n")
	b.WriteString("Content-Length: ")
	b.WriteString(fmt.Sprintf("%d", len(body)))
	b.WriteString("\r\nConnection: close\r\n\r\n")
	b.Write(body)
	return b.Bytes()
}

// readHTTPResponse reads a full HTTP/1.1 response from r and returns the body.
func readHTTPResponse(r io.Reader) ([]byte, error) {
	br := newBufReader(r)
	// Read status line.
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("meeklike: read status: %w", err)
	}
	_ = statusLine
	// Read headers until blank line.
	contentLength := -1
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("meeklike: read header: %w", err)
		}
		line = trimCRLF(line)
		if line == "" {
			break
		}
		// Parse "Content-Length: N"
		if len(line) > 15 && equalFold(line[:15], "Content-Length:") {
			val := trimSpace(line[15:])
			n := 0
			for _, c := range []byte(val) {
				if c < '0' || c > '9' {
					n = -1
					break
				}
				n = n*10 + int(c-'0')
			}
			contentLength = n
		}
	}
	// Read body.
	if contentLength >= 0 {
		body := make([]byte, contentLength)
		_, err := io.ReadFull(br, body)
		if err != nil {
			return nil, fmt.Errorf("meeklike: read body: %w", err)
		}
		return body, nil
	}
	// No Content-Length: read until EOF.
	return io.ReadAll(br)
}

// MeeklikeDialer implements sillad.Dialer, producing a MeeklikePipe. It
// mirrors sillad_meeklike::MeeklikeDialer.
type MeeklikeDialer struct {
	Inner sillad.Dialer
	Key   [32]byte // blake3::hash(key_string)
	Cfg   Config
}

// NewMeeklikeDialer builds a MeeklikeDialer from a key string. The key is
// blake3::hash(key_string), matching the Rust construction.
func NewMeeklikeDialer(inner sillad.Dialer, keyString string, cfg Config) MeeklikeDialer {
	return MeeklikeDialer{
		Inner: inner,
		Key:   blake3.Hash([]byte(keyString)),
		Cfg:   cfg,
	}
}

// Dial implements sillad.Dialer. It creates a DgConnection, starts a virta
// StreamState (pending, client side), runs the ticker, and waits for the
// stream to connect before returning the MeeklikePipe.
func (d MeeklikeDialer) Dial(ctx context.Context) (sillad.Pipe, error) {
	cfg := d.Cfg.withDefaults()
	secret := NewPresharedSecret(d.Key)
	streamID := RandomStreamID()
	dgConn := newDgConnection(ctx, cfg, secret, streamID, d.Inner)

	state, stream := newStreamStatePending(cfg.Mss)
	pipe := newMeeklikePipe(stream, streamID, secret)
	pipe.runTicker(ctx, state, dgConn)

	if err := pipe.waitConnected(ctx); err != nil {
		pipe.Close()
		return nil, err
	}
	return pipe, nil
}

// MeeklikePipe implements sillad.Pipe by wrapping a virta Stream carried over
// a DgConnection. It mirrors sillad_meeklike::MeeklikePipe.
type MeeklikePipe struct {
	stream   *Stream
	streamID StreamID
	secret   *PresharedSecret

	closeOnce sync.Once
	closed    chan struct{}
	connected chan struct{}

	// remoteAddr is a best-effort string (the Rust impl returns "0.0.0.0:0").
	remoteAddr string
}

func newMeeklikePipe(stream *Stream, streamID StreamID, secret *PresharedSecret) *MeeklikePipe {
	return &MeeklikePipe{
		stream:    stream,
		streamID:  streamID,
		secret:    secret,
		closed:    make(chan struct{}),
		connected: make(chan struct{}),
		remoteAddr: "0.0.0.0:0",
	}
}

// runTicker starts the background goroutine that drives the virta StreamState,
// ferrying outgoing StreamMessages to the DgConnection and injecting incoming
// StreamMessages from it. Mirrors the Rust `ticker` function.
func (p *MeeklikePipe) runTicker(ctx context.Context, state *streamState, dgConn *DgConnection) {
	notify := make(chan struct{}, 1)
	notifyTick := func() {
		select {
		case notify <- struct{}{}:
		default:
		}
	}

	var mu sync.Mutex

	// "up" loop: tick the state, send outgoing messages, schedule next tick.
	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		var nextTick time.Time
		// Prime: tick once immediately.
		notifyTick()
		for {
			select {
			case <-p.closed:
				return
			case <-ctx.Done():
				return
			case <-notify:
			case <-tickAfter(nextTick):
			}

			mu.Lock()
			now := time.Now()
			nt, ok := state.tick(now, func(msg StreamMessage) {
				encoded, err := msg.MarshalStdcode()
				if err != nil {
					return
				}
				dgConn.Send(encoded)
			})
			mu.Unlock()
			if !ok {
				return
			}
			nextTick = nt
			// If the stream just became connected, signal waiters.
			p.signalConnected()
		}
	}()

	// "dn" loop: receive datagrams, decode StreamMessages, inject into state.
	dnDone := make(chan struct{})
	go func() {
		defer close(dnDone)
		for {
			bts, err := dgConn.Recv()
			if err != nil {
				return
			}
			var msg StreamMessage
			if err := msg.UnmarshalStdcode(bts); err != nil {
				continue
			}
			mu.Lock()
			state.injectIncoming(msg)
			mu.Unlock()
			notifyTick()
		}
	}()

	// When either loop exits, close the pipe.
	go func() {
		select {
		case <-upDone:
		case <-dnDone:
		}
		p.Close()
	}()
}

// signalConnected closes the connected channel once the stream is connected.
func (p *MeeklikePipe) signalConnected() {
	select {
	case <-p.connected:
		// already signaled
	default:
		if p.stream.queues.isConnected() {
			close(p.connected)
		}
	}
}

// waitConnected blocks until the virta stream is established or ctx is done.
func (p *MeeklikePipe) waitConnected(ctx context.Context) error {
	select {
	case <-p.connected:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-p.closed:
		return errors.New("meeklike: pipe closed before connect")
	}
}

// tickAfter returns a channel that fires at time t (or immediately if t is
// zero/already-past). If t is the zero value, returns nil (never fires) so the
// caller must rely on notify.
func tickAfter(t time.Time) <-chan time.Time {
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d < 0 {
		d = 0
	}
	return time.After(d)
}

// Read implements net.Conn / sillad.Pipe.
func (p *MeeklikePipe) Read(b []byte) (int, error) {
	return p.stream.Read(b)
}

// Write implements net.Conn / sillad.Pipe.
func (p *MeeklikePipe) Write(b []byte) (int, error) {
	return p.stream.Write(b)
}

// Close implements net.Conn / sillad.Pipe. It closes the virta stream and
// signals the ticker goroutines to exit.
func (p *MeeklikePipe) Close() error {
	p.closeOnce.Do(func() {
		p.stream.Close()
		close(p.closed)
	})
	return nil
}

// LocalAddr implements net.Conn.
func (p *MeeklikePipe) LocalAddr() net.Addr { return nil }

// RemoteAddr implements net.Conn.
func (p *MeeklikePipe) RemoteAddr() net.Addr { return nil }

// SetDeadline implements net.Conn.
func (p *MeeklikePipe) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline implements net.Conn.
func (p *MeeklikePipe) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline implements net.Conn.
func (p *MeeklikePipe) SetWriteDeadline(t time.Time) error { return nil }

// Protocol implements sillad.Pipe.
func (p *MeeklikePipe) Protocol() string { return "meeklike" }

// RemoteAddrStr implements sillad.Pipe.
func (p *MeeklikePipe) RemoteAddrStr() string { return p.remoteAddr }

// SharedSecret implements sillad.Pipe. meeklike does not expose a transport
// shared secret for the exit handshake (it carries picomux traffic directly),
// so this returns nil, matching the Rust impl which has no shared_secret.
func (p *MeeklikePipe) SharedSecret() []byte { return nil }

// Ensure MeeklikePipe and MeeklikeDialer satisfy the sillad interfaces.
var (
	_ sillad.Pipe   = (*MeeklikePipe)(nil)
	_ sillad.Dialer = MeeklikeDialer{}
)
