package session_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/goose-network/geph5-go/internal/brokerproto"
	"github.com/goose-network/geph5-go/internal/config"
	"github.com/goose-network/geph5-go/internal/database"
	"github.com/goose-network/geph5-go/internal/exitlib"
	"github.com/goose-network/geph5-go/internal/session"
)

// TestDialThroughOneOffSession exercises Manager.DialThrough end to end against
// an in-process exit (internal/exitlib). A pre-established transport conn (via)
// — standing in for the upstream hop's tunnel in a goose chain — carries the
// conntest ping, the X25519 handshake, picomux, and a tunnel to a loopback HTTP
// target. The background session pool is never started (Manager.Run is not
// called): DialThrough is a synchronous one-off, exactly as the chained path uses
// it. exitlib performs no credential verification, so a nil auth manager (empty
// credentials) is accepted.
func TestDialThroughOneOffSession(t *testing.T) {
	// The "internet": a loopback HTTP target.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	target := fmt.Sprintf("127.0.0.1:%d", port)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "dial-through:%s", r.URL.Path)
	})}
	go srv.Serve(ln)
	defer srv.Close()

	// In-process exit, allowing loopback targets.
	exit, err := exitlib.Start(context.Background(), exitlib.Options{AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	defer exit.Close()

	db, err := database.New("")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		ExitConstraint: brokerproto.ExitConstraint{
			Kind:   "direct",
			Direct: exit.C2EAddr() + "/" + exit.PubkeyHex(),
		},
	}
	m := session.NewManager(cfg, nil, nil, db, nil)

	// via: a transport conn that already reaches the exit's c2e listener — the
	// upstream hop's tunnel in a real chain. DialThrough must ride it, not dial
	// the exit again from the local network.
	via, err := net.DialTimeout("tcp", exit.C2EAddr(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := m.DialThrough(ctx, via, "tcp", target)
	if err != nil {
		t.Fatalf("DialThrough: %v", err)
	}
	defer conn.Close()

	// Real HTTP through the one-off tunnel.
	req, err := http.NewRequest(http.MethodGet, "http://"+target+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(body) != "dial-through:/x" {
		t.Fatalf("body = %q", string(body))
	}
	t.Logf("one-off chained tunnel ok (%d bytes)", len(body))
}

// TestDialThroughRejectsNonDirect verifies the chaining guard: only a pinned
// "direct" exit constraint can ride a single upstream conn (a race/auto route
// dials the transport more than once). The general auto outbound must be
// rejected rather than silently collapsing the chain.
func TestDialThroughRejectsNonDirect(t *testing.T) {
	db, err := database.New("")
	if err != nil {
		t.Fatal(err)
	}
	m := session.NewManager(&config.Config{}, nil, nil, db, nil) // auto constraint
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	_, err = m.DialThrough(context.Background(), c1, "tcp", "example.com:443")
	if err == nil {
		t.Fatal("DialThrough with an auto constraint must fail")
	}
}