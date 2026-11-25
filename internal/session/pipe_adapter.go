// pipe_adapter.go wraps a picomux.Stream in the sillad.Pipe interface so the
// session manager can return opened tunnels as the same Pipe type the proxy
// servers consume.
//
// The Rust session::open_conn returns the picomux::Stream directly as a
// Box<dyn sillad::Pipe> because the Rust picomux::Stream already implements
// sillad::Pipe (protocol() = "picomux", remote_addr() = the mux's remote
// address, shared_secret() = None). The Go picomux.Stream is a plain net.Conn
// without the metadata methods, so we wrap it here.
package session

import (
	"net"
	"time"

	"github.com/goose-network/geph5-go/internal/picomux"
	"github.com/goose-network/geph5-go/internal/sillad"
)

// streamPipe adapts a picomux.Stream to sillad.Pipe.
type streamPipe struct {
	*picomux.Stream
	protocol  string
	remoteStr string
}

// newStreamPipe wraps s with the given protocol label and remote address
// string. protocol is "picomux" (matching Rust picomux::Stream::protocol()).
func newStreamPipe(s *picomux.Stream, remoteStr string) sillad.Pipe {
	return &streamPipe{Stream: s, protocol: "picomux", remoteStr: remoteStr}
}

func (p *streamPipe) Protocol() string      { return p.protocol }
func (p *streamPipe) RemoteAddrStr() string { return p.remoteStr }
func (p *streamPipe) SharedSecret() []byte  { return nil }

// LocalAddr / RemoteAddr / SetDeadline etc. are inherited from *picomux.Stream
// (which embeds the underlying net.Conn accessors). The net.Conn Read/Write/
// Close methods are also inherited.

// oneShotStreamPipe is a stream returned by Manager.DialThrough: a single
// tunnel over a one-off mux established for one chained dial. Unlike a pooled
// session (which lives until the manager tears it down), this mux exists only
// for this stream, so Close tears down the mux — which closes the underlying
// transport (the upstream tunnel conn) too. Without this the mux's read/ping
// goroutines and the upstream conn would leak per dial.
type oneShotStreamPipe struct {
	*streamPipe
	mux *picomux.PicoMux
}

func (p *oneShotStreamPipe) Close() error {
	// Close the mux FIRST. PicoMux.die closes recvCh for every stream still in
	// its map (unblocking any Read parked on <-recvCh, which has no select on
	// deadCh), then clears the map and closes the transport. Closing the stream
	// first would delete it from the map, so die would never close its recvCh
	// and a concurrent blocked Read would leak forever — violating the net.Conn
	// contract that Close unblocks pending reads (goose's Bridge relay goroutine
	// parks in upstream.Read on teardown). The stream FIN is then best-effort
	// over the already-closed transport; the FIN itself is moot once the whole
	// one-off session is gone.
	err := p.mux.Close()
	_ = p.streamPipe.Close()
	return err
}

// Ensure streamPipe satisfies sillad.Pipe (net.Conn + the three metadata
// methods).
var (
	_ sillad.Pipe = (*streamPipe)(nil)
	_ net.Conn    = (*streamPipe)(nil)
	_ sillad.Pipe = (*oneShotStreamPipe)(nil)
	_ net.Conn    = (*oneShotStreamPipe)(nil)
)

// deadline passthroughs to satisfy net.Conn fully (picomux.Stream already
// implements these, but list them explicitly so the interface is unambiguous).
func (p *streamPipe) LocalAddr() net.Addr                { return p.Stream.LocalAddr() }
func (p *streamPipe) RemoteAddr() net.Addr               { return p.Stream.RemoteAddr() }
func (p *streamPipe) SetDeadline(t time.Time) error      { return p.Stream.SetDeadline(t) }
func (p *streamPipe) SetReadDeadline(t time.Time) error  { return p.Stream.SetReadDeadline(t) }
func (p *streamPipe) SetWriteDeadline(t time.Time) error { return p.Stream.SetWriteDeadline(t) }
