// Embedded production-network defaults for the geph provider's zero-config
// case — the geph analogue of the psiphon plugin's embedded production config
// (goose-plugin-psiphon/defaults.go). With no config_path, no embedded_exit,
// and no inline exit_constraint/broker, the provider synthesizes a client
// config pointed at the real geph5 broker so it retrieves the live exit roster
// out of the box, exactly as psiphon downloads its signed server list with no
// operator-supplied file.
//
// The broker URL is the production direct endpoint (the canonical geph5-app
// default-config.yaml's tunneled_broker). The app template's priority_race of
// aws_lambda + domain-fronted sources is not wired in the Go port (clientlib
// supports only direct/fronted), and its fronted fronts are dead, so the
// direct endpoint — verified to serve get_net_status — is the embedded default.
//
// Retrieving the roster (get_net_status) needs no account; establishing a
// tunnel session does (geph is freemium — the production broker rejects the
// test_dummy credential). So the embedded defaults make the provider DISCOVER
// and advertise the real exit list zero-config, while a credential remains
// operator-supplied for traffic. This mirrors psiphon, whose per-server
// outbounds are advertised from the datastore independently of the main tunnel.
package geph

import (
	"github.com/goose-network/geph5-go/internal/brokerproto"
	"github.com/goose-network/geph5-go/internal/config"
)

// defaultBrokerURL is the production geph5 broker's direct RPC endpoint.
const defaultBrokerURL = "https://broker.geph.io"

// defaultBrokerKeys are the production broker verification keys, copied from
// the canonical geph5-app default-config.yaml (broker_keys). They are stable
// network parameters, not secrets: master signs exit routes, the mizaru keys
// verify blinded-token issuance, and mizaru_bw is the bandwidth-token RSA key.
var defaultBrokerKeys = config.BrokerKeys{
	Master:     "88c1d2d4197bed815b01a22cadfc6c35aa246dddb553682037a118aebfaa3954",
	MizaruFree: "0558216cbab7a9c46f298f4c26e171add9af87d0694988b8a8fe52ee932aa754",
	MizaruPlus: "cf6f58868c6d9459b3a63bc2bd86165631b3e916bad7f62b578cd9614e0bcb3b",
	MizaruBw:   "3082010a0282010100d0ae53a794ea37bf2e100cb3a872177ec6c11e8375fdcbf92960ce0293465674eb1426a1841b7622a58979a5ff3f8aa2301a621545e9b90bb39d1a6bfda19d6ca1aae74a3192ddfd2b9558eb652c3c2c22f42bdde272852fb67d93cae5846213512c474bf799844aee019bf718f6fa64223be06364459fc8dec66796b141d450d730c4fffe1cac7df8f05591560afa44bcf274f6c0e2303b39c21ab09d19b459ee594512b8341f3d407c026e2509f42c6d89f82f6a3a36fd5c05ad423cd99ad39089403eb9122ea60ef6648afff65438e8e26ce41fa55b9b18741965c77a627bae947bd38fc345e9adab42d6c458f6e194e4232cfd3f04924d5a5e932fe769610203010001",
}

// zeroConfigProduction reports whether pc is the genuinely-empty production
// case the embedded defaults apply to: no config_path base, no inline exit
// constraint or broker, and no enabled embedded_exit. Any of those means the
// operator chose a specific mode (direct pin, custom broker, static YAML, or
// standalone exit) and the defaults must not inject a broker/keys into it.
func zeroConfigProduction(pc providerConfig) bool {
	if pc.ConfigPath != "" || len(pc.ExitConstraint) != 0 || len(pc.Broker) != 0 {
		return false
	}
	if len(pc.EmbeddedExit) != 0 {
		_, enabled, err := parseEmbeddedExit(pc.EmbeddedExit)
		if err != nil || enabled {
			return false
		}
	}
	return true
}

// applyProductionDefaults fills the unset fields of a zero-config client config
// with the embedded production network parameters: the auto exit constraint,
// the direct production broker, and its verification keys. It only fills what
// is still empty, so it is safe to call after the inline overlays.
func applyProductionDefaults(cfg *config.Config) {
	if cfg.ExitConstraint.Kind == "" {
		cfg.ExitConstraint = brokerproto.AutoConstraint()
	}
	if cfg.Broker == nil {
		cfg.Broker = &config.BrokerSource{Kind: "direct", Direct: defaultBrokerURL}
	}
	if cfg.BrokerKeys == nil {
		keys := defaultBrokerKeys
		cfg.BrokerKeys = &keys
	}
}