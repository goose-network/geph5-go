package dialer

import (
	"context"
	"testing"
	"time"

	"github.com/geph-official/geph5-go/internal/brokerproto"
	"github.com/geph-official/geph5-go/internal/sillad"
)

func TestSplitOnce(t *testing.T) {
	before, after, ok := splitOnce("host:port/pubkeyhex", '/')
	if !ok || before != "host:port" || after != "pubkeyhex" {
		t.Fatalf("splitOnce got %q %q %v", before, after, ok)
	}
	if _, _, ok := splitOnce("nope", '/'); ok {
		t.Fatal("expected ok=false when sep missing")
	}
}

func TestExitRouteIsUnexpired(t *testing.T) {
	now := uint64(time.Now().Unix())
	cases := []struct {
		expiry uint64
		want   bool
	}{
		{now + 1, true},
		{now, false},
		{now - 1, false},
	}
	for _, c := range cases {
		r := brokerproto.ExitRouteDescriptor{Exit: brokerproto.ExitDescriptor{Expiry: c.expiry}}
		if got := exitRouteIsUnexpired(r); got != c.want {
			t.Errorf("expiry=%d: got %v want %v", c.expiry, got, c.want)
		}
	}
}

func TestCombineExitRouteWrapsDirectPath(t *testing.T) {
	exit := brokerproto.ExitDescriptor{C2EListen: "127.0.0.1:9000"}
	route := brokerproto.RouteDescriptor{Kind: "tcp", TcpAddr: "127.0.0.1:9002"}

	// allowDirect=false: route returned unchanged.
	combined := combineExitRoute(exit, route, false)
	if combined.Kind != "tcp" || combined.TcpAddr != "127.0.0.1:9002" {
		t.Fatalf("allowDirect=false should return route unchanged, got %+v", combined)
	}

	// allowDirect=true: Race[ConnTest{ping_count:1, lower:Tcp(c2e)}, Delay{1000, lower:route}].
	combined = combineExitRoute(exit, route, true)
	if combined.Kind != "race" || len(combined.Routes) != 2 {
		t.Fatalf("expected race with 2 routes, got %+v", combined)
	}
	first := combined.Routes[0]
	if first.Kind != "conntest" || first.PingCount != 1 {
		t.Fatalf("first race route should be conntest ping_count=1, got %+v", first)
	}
	if first.Lower == nil || first.Lower.Kind != "tcp" || first.Lower.TcpAddr != "127.0.0.1:9000" {
		t.Fatalf("first race lower should be tcp c2e_listen, got %+v", first.Lower)
	}
	second := combined.Routes[1]
	if second.Kind != "delay" || second.Milliseconds != 1000 {
		t.Fatalf("second race route should be delay 1000ms, got %+v", second)
	}
	if second.Lower == nil || second.Lower.Kind != "tcp" || second.Lower.TcpAddr != "127.0.0.1:9002" {
		t.Fatalf("second race lower should be the original route, got %+v", second.Lower)
	}
}

func TestRouteToDialerKinds(t *testing.T) {
	// tcp -> BoundTcpDialer
	d := routeToDialer(&brokerproto.RouteDescriptor{Kind: "tcp", TcpAddr: "1.2.3.4:80"}, nil)
	if _, ok := d.(BoundTcpDialer); !ok {
		t.Fatalf("tcp route should compile to BoundTcpDialer, got %T", d)
	}

	// other -> FailingDialer
	d = routeToDialer(&brokerproto.RouteDescriptor{Kind: "other", Other: []byte("null")}, nil)
	if _, ok := d.(sillad.FailingDialer); !ok {
		t.Fatalf("other route should compile to FailingDialer, got %T", d)
	}

	// unknown -> FailingDialer
	d = routeToDialer(&brokerproto.RouteDescriptor{Kind: "wat"}, nil)
	if _, ok := d.(sillad.FailingDialer); !ok {
		t.Fatalf("unknown route should compile to FailingDialer, got %T", d)
	}

	// race with two tcp routes -> RaceDialer
	race := brokerproto.RouteDescriptor{Kind: "race", Routes: []brokerproto.RouteDescriptor{
		{Kind: "tcp", TcpAddr: "1.1.1.1:1"},
		{Kind: "tcp", TcpAddr: "2.2.2.2:2"},
	}}
	d = routeToDialer(&race, nil)
	rd, ok := d.(sillad.RaceDialer)
	if !ok {
		t.Fatalf("race route should compile to RaceDialer, got %T", d)
	}
	if len(rd.Inner) != 2 {
		t.Fatalf("expected 2 inner dialers, got %d", len(rd.Inner))
	}

	// empty race -> FailingDialer
	d = routeToDialer(&brokerproto.RouteDescriptor{Kind: "race"}, nil)
	if _, ok := d.(sillad.FailingDialer); !ok {
		t.Fatalf("empty race should compile to FailingDialer, got %T", d)
	}

	// fallback with two routes -> FallbackDialer
	fb := brokerproto.RouteDescriptor{Kind: "fallback", Routes: []brokerproto.RouteDescriptor{
		{Kind: "tcp", TcpAddr: "1.1.1.1:1"},
		{Kind: "tcp", TcpAddr: "2.2.2.2:2"},
	}}
	d = routeToDialer(&fb, nil)
	fd, ok := d.(sillad.FallbackDialer)
	if !ok {
		t.Fatalf("fallback route should compile to FallbackDialer, got %T", d)
	}
	if len(fd.Inner) != 2 {
		t.Fatalf("expected 2 inner dialers, got %d", len(fd.Inner))
	}

	// timeout -> TimeoutDialer
	tcpLower := brokerproto.RouteDescriptor{Kind: "tcp", TcpAddr: "1.2.3.4:80"}
	to := brokerproto.RouteDescriptor{Kind: "timeout", Milliseconds: 500, Lower: &tcpLower}
	d = routeToDialer(&to, nil)
	td, ok := d.(sillad.TimeoutDialer)
	if !ok {
		t.Fatalf("timeout route should compile to TimeoutDialer, got %T", d)
	}
	if td.Timeout != 500*time.Millisecond {
		t.Fatalf("expected 500ms timeout, got %v", td.Timeout)
	}

	// delay -> DelayDialer
	dl := brokerproto.RouteDescriptor{Kind: "delay", Milliseconds: 1000, Lower: &tcpLower}
	d = routeToDialer(&dl, nil)
	dd, ok := d.(sillad.DelayDialer)
	if !ok {
		t.Fatalf("delay route should compile to DelayDialer, got %T", d)
	}
	if dd.Delay != 1000*time.Millisecond {
		t.Fatalf("expected 1000ms delay, got %v", dd.Delay)
	}

	// conntest -> conntest.Dialer
	ct := brokerproto.RouteDescriptor{Kind: "conntest", PingCount: 3, Lower: &tcpLower}
	d = routeToDialer(&ct, nil)
	if _, ok := d.(interface {
		Dial(context.Context) (sillad.Pipe, error)
	}); !ok {
		t.Fatalf("conntest route should compile to a Dialer, got %T", d)
	}

	// hex -> hexdialer.Dialer
	hx := brokerproto.RouteDescriptor{Kind: "hex", Lower: &tcpLower}
	d = routeToDialer(&hx, nil)
	if _, ok := d.(interface {
		Dial(context.Context) (sillad.Pipe, error)
	}); !ok {
		t.Fatalf("hex route should compile to a Dialer, got %T", d)
	}
}

func TestGetDialerDirectParsesPubkey(t *testing.T) {
	// Use a loopback that won't actually be dialed (we only check parsing here
	// by calling getDialerDirect, which resolves the host but does not connect).
	// Use an IP literal so no DNS lookup is needed.
	pubkeyHex := "0000000000000000000000000000000000000000000000000000000000000000"
	pub, exit, dialer, err := getDialerDirect(t.Context(), "127.0.0.1:9999/"+pubkeyHex, nil)
	if err != nil {
		t.Fatalf("getDialerDirect failed: %v", err)
	}
	if len(pub) != 32 {
		t.Fatalf("expected 32-byte pubkey, got %d", len(pub))
	}
	if exit.C2EListen != "0.0.0.0:0" || exit.B2EListen != "0.0.0.0:0" || exit.Expiry != 0 {
		t.Fatalf("unexpected placeholder exit: %+v", exit)
	}
	if dialer == nil {
		t.Fatal("expected non-nil dialer")
	}
}

func TestGetDialerDirectRejectsBadPubkey(t *testing.T) {
	// Missing / separator.
	if _, _, _, err := getDialerDirect(t.Context(), "127.0.0.1:9999", nil); err == nil {
		t.Fatal("expected error for missing / in direct constraint")
	}
	// Bad hex.
	if _, _, _, err := getDialerDirect(t.Context(), "127.0.0.1:9999/zz", nil); err == nil {
		t.Fatal("expected error for bad hex pubkey")
	}
	// Wrong length (not 32 bytes).
	if _, _, _, err := getDialerDirect(t.Context(), "127.0.0.1:9999/00", nil); err == nil {
		t.Fatal("expected error for wrong-length pubkey")
	}
}
