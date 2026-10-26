// Command psessmgr runs the real session manager against the real exit and
// issues OpenConn through it — the exact code path the client binary uses —
// to reproduce the tunnel-open EOF with full control over logging.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/config"
	"github.com/geph-official/geph5-go/internal/database"
	"github.com/geph-official/geph5-go/internal/session"
	"github.com/geph-official/geph5-go/internal/tunnelcmd"
)

func main() {
	target := os.Getenv("TARGET")
	if target == "" {
		target = "223.5.5.5:80"
	}
	constraintStr := os.Getenv("CONSTRAINT")
	if constraintStr == "" {
		constraintStr = "127.0.0.1:39001/41e566edd35836641cec7b410508577d4001e8a77ad68681590d201e0bb405cd"
	}

	cfg := &config.Config{}
	cfg.Broker = nil
	if err := json.Unmarshal([]byte(`{"direct":`+fmt.Sprintf("%q", constraintStr)+`}`), &cfg.ExitConstraint); err != nil {
		panic(err)
	}

	db, err := database.New("")
	if err != nil {
		panic(err)
	}
	mgr := session.NewManager(cfg, nil, nil, db, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mgr.Run(ctx)

	// Wait for one live session.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) && len(mgr.LiveSessionInfos()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	if len(mgr.LiveSessionInfos()) == 0 {
		fmt.Println("no session within 90s")
		return
	}
	fmt.Println("session is live; opening tunnel to", target)

	pipe, err := mgr.OpenConn(ctx, "tcp", target)
	if err != nil {
		fmt.Println("OpenConn error:", err)
		return
	}
	fmt.Println("tunnel object obtained")
	// NOTE: OpenConn already consumed the RichTunnelResponse (as Rust
	// open_conn does); the returned stream carries the tunneled payload.
	resp := tunnelcmd.RichTunnelResponse{}
	_ = resp

	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\n\r\n", target)
	if err := pipe.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		fmt.Println("SetWriteDeadline:", err)
	}
	if _, err := pipe.Write([]byte(req)); err != nil {
		fmt.Println("write err:", err)
		return
	}
	_ = pipe.SetReadDeadline(time.Now().Add(15 * time.Second))
	body, err := io.ReadAll(pipe)
	fmt.Printf("body (%d bytes, err=%v):\n%.200s\n", len(body), err, string(body))
}

var _ = brokerproto.ExitConstraint{}
