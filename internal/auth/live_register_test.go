package auth

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goose-network/geph5-go/internal/brokerproto"
	"github.com/goose-network/geph5-go/internal/config"
	"github.com/goose-network/geph5-go/internal/database"
	"github.com/goose-network/geph5-go/internal/frontedhttp"
)

// connectDialer returns a stack dialer that tunnels TCP through an HTTP CONNECT
// proxy (clash's mixed port at 127.0.0.1:7890). The returned conn reaches addr
// directly, so frontedhttp's TLS handshake rides the tunnel.
func connectDialer(proxyAddr string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 30 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("dial proxy: %w", err)
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			return nil, err
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("CONNECT read: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("CONNECT %s: %s", addr, resp.Status)
		}
		_ = conn.SetDeadline(time.Time{})
		if br.Buffered() > 0 {
			return &bufferedConn{Conn: conn, r: br}, nil
		}
		return conn, nil
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// TestLiveRegistration drives the REAL auth path against broker.geph.io through
// the clash proxy: self-registration via melpow proof-of-work, auth token,
// connect-token refresh (Plus->Free WrongLevel fallback for a fresh Free
// account), and a signed get_exit_route fetch + verification. This is the
// definitive end-to-end arbiter for the geph data-path fixes. It only runs when
// GEPH_LIVE=1 (network + PoW), so it stays out of CI and normal test runs.
func TestLiveRegistration(t *testing.T) {
	if os.Getenv("GEPH_LIVE") != "1" {
		t.Skip("set GEPH_LIVE=1 to run the live broker registration test")
	}
	proxy := os.Getenv("GEPH_PROXY")
	if proxy == "" {
		proxy = "127.0.0.1:7890"
	}
	const master = "88c1d2d4197bed815b01a22cadfc6c35aa246dddb553682037a118aebfaa3954"
	cfg := &config.Config{
		Broker:         &config.BrokerSource{Kind: "direct", Direct: "https://broker.geph.io"},
		ExitConstraint: brokerproto.AutoConstraint(),
		BrokerKeys: &config.BrokerKeys{
			Master:     master,
			MizaruFree: "0558216cbab7a9c46f298f4c26e171add9af87d0694988b8a8fe52ee932aa754",
			MizaruPlus: "cf6f58868c6d9459b3a63bc2bd86165631b3e916bad7f62b578cd9614e0bcb3b",
		},
	}
	transport, err := frontedhttp.New("https://broker.geph.io", "", nil, connectDialer(proxy))
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	broker := brokerproto.NewBrokerClient(transport)
	db, err := database.New(filepath.Join(t.TempDir(), "live.db"))
	if err != nil {
		t.Fatalf("database: %v", err)
	}
	mgr := NewManager(cfg, db, broker)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// 1. Registration PoW + auth token (synchronous; ensureCredential runs here).
	t0 := time.Now()
	token, err := mgr.GetAuthToken(ctx)
	if err != nil {
		t.Fatalf("GetAuthToken (registration): %v", err)
	}
	t.Logf("registered + auth token in %s (secret kind=%q, token len=%d)", time.Since(t0).Round(time.Millisecond), cfg.Credentials.Kind, len(token))
	if cfg.Credentials.Kind != "secret" || cfg.Credentials.Secret == "" {
		t.Fatalf("credential not a registered secret: %+v", cfg.Credentials)
	}

	// 2. Connect-token refresh (AuthLoop) then fetch the current-epoch token.
	go func() { _ = mgr.AuthLoop(ctx) }()
	ct, err := mgr.GetConnectToken(ctx)
	if err != nil {
		t.Fatalf("GetConnectToken: %v", err)
	}
	t.Logf("connect token level=%s (ISPlus=%v)", ct.Level, ISPlus.Load())

	// 3. Signed exit-route fetch + verification (the data-path envelope).
	tokenJSON, err := json.Marshal(ct.Token)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}
	sigJSON, err := json.Marshal(ct.Sig)
	if err != nil {
		t.Fatalf("marshal sig: %v", err)
	}
	args := brokerproto.GetExitRouteArgs{
		Token:          tokenJSON,
		Sig:            sigJSON,
		ExitConstraint: brokerproto.AutoConstraint(),
		ClientMetadata: json.RawMessage(`{"version":"0.4.0"}`),
	}
	signed, err := broker.GetExitRoute(ctx, args)
	if err != nil {
		t.Fatalf("GetExitRoute: %v", err)
	}
	var route brokerproto.ExitRouteDescriptor
	validator := func(pk [32]byte) bool { return hex.EncodeToString(pk[:]) == master }
	if err := signed.Verify(brokerproto.DomainExitRoute, validator, &route); err != nil {
		t.Fatalf("verify exit route signature: %v", err)
	}
	t.Logf("exit route OK: exit=%s c2e=%s route kind=%q", route.ExitPubkeyHex(), route.Exit.C2EListen, route.Route.Kind)
	if route.Exit.C2EListen == "" {
		t.Fatal("exit route has empty c2e_listen")
	}
	// NOTE: a per-exit pin uses the client-side "direct" (c2e/pubkey) constraint,
	// which GetDialer resolves locally (getDialerDirect) — it must NOT be sent to
	// the broker ("direct constraints must not be sent to the broker"). That path
	// is exercised by the dialer unit tests and the goose openrung->geph chain test.
}