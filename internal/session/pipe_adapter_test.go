package session

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/goose-network/geph5-go/internal/picomux"
)

// TestOneShotStreamPipeCloseUnblocksRead is a regression test for the Close
// ordering of the one-off chained stream. Close must unblock a Read parked on
// the stream's recvCh (net.Conn's Close contract). Closing the stream FIRST
// deletes it from the mux's map, so mux.die — which closes recvCh only for
// streams still in the map — never closes this stream's recvCh, and a concurrent
// blocked Read leaks forever (goose's Bridge relay goroutine parks in
// upstream.Read on teardown). mux.Close must run first. With the wrong order
// this test hangs until the deadline; with the right order Read returns EOF.
func TestOneShotStreamPipeCloseUnblocksRead(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	// Drain the peer so the mux's SYN/frame writes never block on the
	// synchronous pipe.
	go io.Copy(io.Discard, c2)

	mux := picomux.New(c1)
	stream, err := mux.Open([]byte("null"))
	if err != nil {
		t.Fatal(err)
	}
	osp := &oneShotStreamPipe{
		streamPipe: &streamPipe{Stream: stream, protocol: "picomux", remoteStr: "test"},
		mux:        mux,
	}

	done := make(chan error, 1)
	go func() {
		_, err := osp.Read(make([]byte, 1))
		done <- err
	}()
	// Give the reader time to pass the closed guard and park on <-recvCh.
	time.Sleep(50 * time.Millisecond)

	osp.Close()

	select {
	case err := <-done:
		if err != io.EOF {
			t.Logf("Read returned %v after Close (want io.EOF)", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock the pending Read — goroutine leak (stream closed before mux)")
	}
}