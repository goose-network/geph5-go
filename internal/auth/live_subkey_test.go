package auth

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/goose-network/geph5-go/internal/brokerproto"
	"github.com/goose-network/geph5-go/internal/frontedhttp"
	"github.com/goose-network/geph5-go/internal/mizaru2"
)

// TestLiveSubkeyFormat captures the real broker get_mizaru_subkey DER and
// reports whether it parses as PKCS#1 or PKIX/SPKI. No account/PoW needed.
// Runs only with GEPH_LIVE=1.
func TestLiveSubkeyFormat(t *testing.T) {
	if os.Getenv("GEPH_LIVE") != "1" {
		t.Skip("set GEPH_LIVE=1")
	}
	proxy := os.Getenv("GEPH_PROXY")
	if proxy == "" {
		proxy = "127.0.0.1:7890"
	}
	transport, err := frontedhttp.New("https://broker.geph.io", "", nil, connectDialer(proxy))
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	broker := brokerproto.NewBrokerClient(transport)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	epoch := mizaru2.CurrentEpoch()
	for _, level := range []brokerproto.AccountLevel{brokerproto.AccountLevelPlus, brokerproto.AccountLevelFree} {
		der, err := broker.GetMizaruSubkey(ctx, level, epoch)
		if err != nil {
			t.Fatalf("GetMizaruSubkey(%s): %v", level, err)
		}
		t.Logf("level=%s epoch=%d subkey len=%d head=%s", level, epoch, len(der), hex.EncodeToString(der[:min(24, len(der))]))
		if _, err := x509.ParsePKCS1PublicKey(der); err != nil {
			t.Logf("  PKCS1 parse: FAIL (%v)", err)
		} else {
			t.Logf("  PKCS1 parse: OK")
		}
		if _, err := x509.ParsePKIXPublicKey(der); err != nil {
			t.Logf("  PKIX  parse: FAIL (%v)", err)
		} else {
			t.Logf("  PKIX  parse: OK")
		}
	}
}