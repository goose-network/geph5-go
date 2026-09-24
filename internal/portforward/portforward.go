// Package portforward ports geph5-client's port_forward module
// (binaries/geph5-client/src/port_forward.rs) to Go.
//
// For each configured PortForwardCfg { Listen, Connect }, Serve binds a
// listener on Listen and loops accepting inbound TCP connections. Each
// accepted connection is paired with a tunneled connection to Connect
// (opened through the provided openConn, which is session.Manager's
// AsOpenConnFunc) and the two are relayed bidirectionally.
//
// The relay mirrors the Rust litecopy + try_join semantics: a half-close
// (EOF) in one direction is propagated to the peer by half-closing that
// direction's writer, but does NOT tear down the other direction; an error
// in either direction short-circuits and ends both. If no forwards are
// configured, Serve blocks forever (Rust: std::future::pending).
package portforward

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"

	"github.com/geph-official/geph5-go/internal/config"
)

// Serve runs the port-forwarding service. It blocks until ctx is cancelled
// or one of the per-forward listener goroutines returns a fatal error. If
// forwards is empty it blocks forever (pending), matching port_forward.rs.
//
// openConn opens a tunneled TCP connection to a "host:port" string; it is
// session.Manager.AsOpenConnFunc() in the wired client.
func Serve(ctx context.Context, forwards []config.PortForwardCfg, openConn func(ctx context.Context, remote string) (net.Conn, error)) error {
	if len(forwards) == 0 {
		// std::future::pending::(): block forever until ctx is cancelled.
		<-ctx.Done()
		return ctx.Err()
	}

	// Each forward runs in its own goroutine. We collect their results and
	// return the first non-nil error (or nil when ctx is cancelled). The
	// per-connection forwarders are owned by their listener goroutine: when
	// the listener stops (ctx cancelled or fatal error), in-flight relays
	// are torn down via the per-forward cancel.
	type result struct {
		err error
	}
	results := make(chan result, len(forwards))

	var wg sync.WaitGroup
	wg.Add(len(forwards))

	for i := range forwards {
		fwd := forwards[i]
		go func() {
			defer wg.Done()
			err := serveOne(ctx, fwd, openConn)
			// A listener returning because ctx was cancelled is not an
			// error worth surfacing.
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				results <- result{err: err}
			} else {
				results <- result{err: nil}
			}
		}()
	}

	// Wait for all listener goroutines to finish, then close the results
	// channel. We use a separate goroutine so the select below can range
	// over results without deadlocking.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	var firstErr error
	for {
		select {
		case r := <-results:
			if r.err != nil && firstErr == nil {
				firstErr = r.err
			}
		case <-done:
			return firstErr
		case <-ctx.Done():
			// ctx cancelled: the listener goroutines will observe it and
			// exit on their own; wait for them so we don't leak listeners.
			<-done
			if firstErr == nil {
				return ctx.Err()
			}
			return firstErr
		}
	}
}

// serveOne binds a listener on fwd.Listen and accepts connections in a loop,
// spawning a relay goroutine per accepted connection. It returns when the
// accept loop exits (ctx cancellation closes the listener).
func serveOne(ctx context.Context, fwd config.PortForwardCfg, openConn func(ctx context.Context, remote string) (net.Conn, error)) error {
	listener, err := net.Listen("tcp", fwd.Listen)
	if err != nil {
		return err
	}

	// Close the listener when ctx is cancelled so Accept unblocks. We
	// deliberately ignore the returned error from listener.Close() here;
	// it is expected to be net.ErrClosed on shutdown.
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		listened, err := listener.Accept()
		if err != nil {
			return err
		}
		log.Printf("portforward: accepted on %s -> %s", fwd.Listen, fwd.Connect)
		// Each connection gets its own goroutine. We do not bound the
		// number of in-flight relays here, matching port_forward.rs which
		// attaches each to a TaskReaper without a concurrency limit.
		go relay(ctx, fwd, listened, openConn)
	}
}

// relay opens a tunneled connection to fwd.Connect and runs a bidirectional
// copy between the listened connection and the tunneled connection.
//
// The copy uses try_join semantics: a half-close (EOF) in one direction is
// propagated by half-closing that direction's writer but does NOT end the
// other direction; an error in either direction ends both. This mirrors
// (litecopy(read_listened, write_connected), litecopy(read_connected,
// write_listened)).try_join().
func relay(ctx context.Context, fwd config.PortForwardCfg, listened net.Conn, openConn func(ctx context.Context, remote string) (net.Conn, error)) {
	// Tear down the listened side if we fail to open the tunneled side.
	connected, err := openConn(ctx, fwd.Connect)
	if err != nil {
		log.Printf("portforward: open_conn to %s failed: %v", fwd.Connect, err)
		listened.Close()
		return
	}
	log.Printf("portforward: started %s -> %s", fwd.Listen, fwd.Connect)

	// Ensure both ends are closed when the relay finishes, regardless of
	// how it ends. The half-closes below propagate EOF to peers; this full
	// close guarantees no fd leak if a direction errored mid-stream.
	defer listened.Close()
	defer connected.Close()

	// Run both copy directions and wait for BOTH to complete (try_join, not
	// race). Each direction, on EOF, half-closes its writer so the peer
	// learns this direction ended; an error is captured and signals the
	// other direction to stop.
	errc := make(chan error, 2)
	go func() { errc <- copyOne(listened, connected) }() // listened -> connected
	go func() { errc <- copyOne(connected, listened) }() // connected -> listened

	// Wait for both directions. If the first to finish reports an error,
	// we close both ends immediately so the other direction unblocks
	// (its io.Copy returns net.ErrClosed or EOF) rather than lingering.
	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil && firstErr == nil {
			firstErr = err
			// Force the other direction to unwind. Closing the conns
			// makes the in-flight io.Copy return promptly.
			listened.Close()
			connected.Close()
		}
	}
	if firstErr != nil {
		log.Printf("portforward: relay %s -> %s ended with error: %v", fwd.Listen, fwd.Connect, firstErr)
	}
}

// copyOne copies a single direction: reader -> writer. On EOF it half-closes
// the writer (propagating the close to the peer) and returns nil, matching
// litecopy's behavior of forwarding the half-close and ignoring a shutdown
// error on an already-gone writer. On any other error it returns it.
func copyOne(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	if err != nil {
		return err
	}
	// EOF reached: forward the half-close. If the writer doesn't support
	// CloseWrite (e.g. the tunneled sillad.Pipe wrapper), fall back to a
	// no-op; the deferred full close in relay handles teardown.
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	return nil
}
