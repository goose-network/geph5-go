// This file adds the SERVER side of geph5's nanorpc transport to the
// nanorpc package, porting `nanorpc-sillad`'s `rpc_serve` and the
// `DialerTransport` client (libraries/nanorpc-sillad/src/lib.rs).
//
// Wire format (identical to the client side in nanorpc.go): each JSON-RPC
// 2.0 request is a single JSON object terminated by "\n"; the server reads
// one line, dispatches it to an RpcService, and writes the JSON-encoded
// JrpcResponse followed by "\n". The transport is newline-delimited, NOT
// length-prefixed. Each connection handles a sequential stream of requests
// (one in flight at a time, matching the Rust implementation which splits
// the connection into a buffered reader and a writer and loops on
// read_line -> respond -> write_all).
//
// On EOF while reading a line, the per-connection loop ends and the
// connection is closed. Context cancellation closes the listener to unblock
// Accept.
package nanorpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/geph-official/geph5-go/internal/sillad"
)

// RpcService dispatches a single decoded JrpcRequest to produce a
// JrpcResponse. It mirrors nanorpc's `RpcService::respond_raw`: the
// implementation is responsible for switching on req.Method, producing the
// result (or error), and echoing req.ID back in the response. The response
// returned here is serialized verbatim to the wire, so the implementation
// must populate Result (json.RawMessage) and/or Error (*JrpcError) and set
// ID = req.ID.
type RpcService interface {
	RespondRaw(ctx context.Context, req *JrpcRequest) *JrpcResponse
}

// Serve runs an accept loop on ln, serving newline-delimited JSON-RPC
// requests to svc. It mirrors `nanorpc_sillad::rpc_serve`: each accepted
// connection is handled in its own goroutine, reading one JSON request per
// line, calling svc.RespondRaw, and writing the JSON response plus "\n".
//
// The loop returns when the listener is closed (either by ctx cancellation
// or by an external closer) or when Accept returns a non-temporary error.
// Per-connection handler goroutines are tracked via a WaitGroup so that
// Serve does not leave stray handlers running after it returns; when ctx is
// cancelled, in-flight handlers are signalled via the per-conn context and
// the listener is closed to unblock Accept.
func Serve(ctx context.Context, ln net.Listener, svc RpcService) error {
	var wg sync.WaitGroup

	// Close the listener when ctx is cancelled so Accept unblocks. Use a
	// once-guarded goroutine rather than ctx.AfterFunc to keep the
	// dependency surface minimal and to ensure we only close once.
	ctxDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-ctxDone:
		}
	}()
	defer close(ctxDone)

	// Wait for all per-connection handlers to finish before returning, so
	// callers can be sure no goroutines outlive Serve (structured
	// concurrency, mirroring the Rust TaskReaper).
	defer wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// If the context was cancelled, the listener close is the
			// expected exit path; surface the context error.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// A closed listener (or any non-temporary error) ends the loop.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// Temporary timeout errors: keep looping.
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			serveConn(ctx, c, svc)
		}(conn)
	}
}

// serveConn handles a single connection: a sequential loop of
// read-line -> dispatch -> write-response, exactly mirroring the Rust
// per-connection handler (BufReader + split read/write).
func serveConn(ctx context.Context, conn net.Conn, svc RpcService) {
	// A per-connection context that is cancelled when the parent ctx is
	// cancelled, so RespondRaw implementations can observe shutdown.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			// EOF (or any read error) ends this connection's loop, matching
			// the Rust `?` on read_line which propagates and ends the task.
			return
		}
		// Trim the trailing newline. The Rust side parses the full line
		// (including the newline) with serde_json, which tolerates trailing
		// whitespace; Go's json.Unmarshal does too, but trimming keeps the
		// behavior explicit and avoids issues with empty lines.
		line = trimNewline(line)
		if len(line) == 0 {
			// Empty line: nothing to dispatch. Skip rather than emit an
			// error response, to stay robust against keepalive-style blank
			// lines (the Rust impl would fail to parse and end the task;
			// we choose to simply continue, which is a safe superset).
			continue
		}

		var req JrpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			// Mirror the Rust `?` on serde_json::from_str: a malformed
			// request ends the connection. We do not attempt to send a
			// JSON-RPC error because we cannot reliably recover the id.
			return
		}

		resp := svc.RespondRaw(ctx, &req)
		if resp == nil {
			// Defensive: a nil response is treated as a JSON-RPC internal
			// error echoing the request id, so the client is not left
			// waiting for a line that never comes.
			resp = &JrpcResponse{
				JSONRPC: "2.0",
				Error: &JrpcError{
					Code:    -32603,
					Message: "Internal error: nil response",
				},
				ID: req.ID,
			}
		}
		// Ensure the wire response always carries the request id and
		// jsonrpc tag, matching the Rust impl which serializes whatever
		// respond_raw returned (the service is expected to set these, but
		// we guarantee them here).
		if resp.ID.IsZero() && !req.ID.IsZero() {
			resp.ID = req.ID
		}
		if resp.JSONRPC == "" {
			resp.JSONRPC = "2.0"
		}

		out, err := json.Marshal(resp)
		if err != nil {
			// Should not happen for our types; end the connection.
			return
		}
		out = append(out, '\n')
		if _, err := conn.Write(out); err != nil {
			// Write error ends the connection, matching the Rust `?` on
			// write_all.
			return
		}
	}
}

// trimNewline removes a single trailing '\n' (and an optional preceding
// '\r') from line. ReadBytes('\n') includes the delimiter, so this mirrors
// Rust's BufReader::read_line behavior of leaving the newline in the
// string before serde_json parses it.
func trimNewline(line []byte) []byte {
	if len(line) == 0 {
		return line
	}
	if line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
	}
	return line
}

// DialerTransport is a nanorpc RpcTransport backed by a sillad.Dialer. It
// mirrors `nanorpc_sillad::DialerTransport<D>`: each CallRaw dials a fresh
// connection (no pooling, matching the Rust TODO), writes the JSON-encoded
// request followed by "\n", then reads exactly one line back and decodes it
// as the JrpcResponse.
//
// NOTE: like the Rust implementation, this opens a new connection per call.
// Connection pooling is intentionally absent.
type DialerTransport struct {
	Dialer sillad.Dialer
}

// Ensure DialerTransport satisfies RpcTransport.
var _ RpcTransport = (*DialerTransport)(nil)

// CallRaw dials, sends the request, and reads the single-line response.
func (t *DialerTransport) CallRaw(ctx context.Context, req *JrpcRequest) (*JrpcResponse, error) {
	if t.Dialer == nil {
		return nil, errors.New("nanorpc: DialerTransport has nil Dialer")
	}
	pipe, err := t.Dialer.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("nanorpc: dial: %w", err)
	}
	defer pipe.Close()

	out, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("nanorpc: marshal request: %w", err)
	}
	out = append(out, '\n')
	if _, err := pipe.Write(out); err != nil {
		return nil, fmt.Errorf("nanorpc: write request: %w", err)
	}

	reader := bufio.NewReader(pipe)
	line, err := reader.ReadBytes('\n')
	if err != nil && (len(line) == 0 || !errors.Is(err, io.EOF)) {
		return nil, fmt.Errorf("nanorpc: read response: %w", err)
	}
	line = trimNewline(line)
	if len(line) == 0 {
		return nil, errors.New("nanorpc: empty response from server")
	}
	var resp JrpcResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("nanorpc: decode response: %w", err)
	}
	return &resp, nil
}
