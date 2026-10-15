# geph — goose provider plugin

This package is the [goose](https://github.com/goose-network/goose) proxy-pool
engine's **geph provider plugin**: it embeds the geph5-go client core as a
library and exposes it to goose as a dynamic source of outbounds. Once the
embedded client has a live tunnel to a geph5 exit, the provider advertises one
`socks5` outbound pointing at the client's loopback SOCKS5 listener; goose
merges it into the provider's managed pool, and every inbound routed through
that pool forwards traffic through real geph5 tunnels:

```
goose inbound ──▶ pool (managed by provider) ──▶ socks5 ──▶ embedded geph5 client
                                                                        │
                                            session manager: 6 tunnels, X25519+ed25519
                                            handshake, picomux, sosistab3
                                                                        │
                                                              Rust geph5-exit ──▶ internet
```

With the `embedded_exit` option the last hop changes: a **Go** geph5 exit
(`geph5-go`'s `internal/exitlib`) runs inside the provider's own process, so
the whole chain — goose engine, geph client, geph exit — is one process with
no Rust binary, no broker, and no external exit (see
[Standalone mode](#standalone-mode-embedded-exit)).

The package lives inside the geph5-go module (not a separate repo) because it
embeds geph5-go's `internal/` packages (`internal/clientlib` → `internal/auth`,
`internal/session`, …), which Go's internal-package rule confines to this
module. On the goose side it imports only
[`goose-plugin-api`](../../goose-plugin-api) — never goose itself — so the
plugin import boundary stays acyclic.

## Bootstrap lifecycle

Establishing a geph5 session means fetching/compiling an exit route, dialing
the exit, completing the X25519+ed25519 handshake, and registering the tunnel —
work the session manager does on its own schedule. The provider therefore
starts the client in a background goroutine from the factory:

- `Outbounds()` returns an **empty set** until the SOCKS5 listener is bound
  *and* at least one session is live, then signals `Watch()` so the engine
  repolls promptly instead of waiting for the 2-minute fallback poll.
- A failed session (broker unreachable, exit down) is retried indefinitely
  inside the session manager; the provider's only terminal error paths are an
  invalid config (fails the factory) and a 5-minute timeout waiting for the
  first session, both surfaced via `Outbounds()`.

## Config

The provider config is a JSON object whose keys overlap the geph5 client
config where they make sense as provider knobs:

```json
{
  "config_path":     "/path/to/geph5.yaml",
  "socks_listen":    "127.0.0.1:0",
  "embedded_exit":   true,
  "outbound_id":     "geph",
  "exit_constraint": { "direct": "host:port/<exit-pubkey-hex>" },
  "secret":          "...",
  "cache":           "/path/to/geph.db",
  "broker":          "https://broker.example.com",
  "broker_keys":     { "master": "<hex>", "mizaru_free": "<hex>", "mizaru_plus": "<hex>", "mizaru_bw": "<hex>" }
}
```

| Key | Default | Meaning |
|---|---|---|
| `config_path` | — | Full client YAML (`config.LoadYAML` format; see the module README) as the base config. |
| `socks_listen` | `127.0.0.1:0` | Address for the embedded client's SOCKS5 listener; `:0` picks an ephemeral loopback port. |
| `embedded_exit` | — | Standalone mode: boot the geph5 exit in-process (see below). `true` or `{ "listen", "allow_loopback", "seed_hex" }`. |
| `outbound_id` | `geph` | The goose outbound id the provider advertises. |
| `exit_constraint` | — | The client's exit constraint in its native enum shape: `"auto"`, `{"direct": "host:port/pubkeyhex"}`, `{"hostname": "..."}`, etc. |
| `credentials` | — | Full credential object, when a broker is used (`{"secret": ...}`, `"test_dummy"`, or `{"legacy_username_password": {...}}`). |
| `secret` | — | Shorthand for `credentials: {secret: ...}`. |
| `username` / `password` | — | Shorthand for the legacy credential. |
| `cache` | in-memory | Persistent client cache (routecache/auth) path. |
| `broker` | — | Broker source: a bare URL string (direct) or a tagged object (`{"fronted": {...}}`). |
| `broker_keys` | — | Broker verification keys, required with a broker. |

`config_path` loads a static YAML; the inline keys (when present) are applied on
top of it, so a shared YAML can be reused while the plugin overrides the
listener or exit constraint.

Three shapes cover the common cases:

- **Broker mode** — set `broker`, `broker_keys`, credentials, and
  `exit_constraint: "auto"` (or a country/id constraint); the session manager
  fetches signed routes like the standalone client.
- **Direct mode** — skip the broker entirely and pin one exit with
  `exit_constraint: {"direct": "host:port/<pubkeyhex>"}` plus `secret`. The
  exit's public key is the ed25519 key derived from its `signing_secret` seed.
- **Standalone mode (embedded exit)** — set `embedded_exit`; see below.

## Standalone mode (embedded exit)

`"embedded_exit": true` boots a geph5 exit server — `geph5-go`'s
`internal/exitlib`, a Go port of the Rust `geph5-exit` serving path — inside
the provider's own process, generates a direct constraint for it, and
overrides whatever `exit_constraint` the config carried. The full chain (goose
engine, geph client, geph exit) then runs in **one process** with no Rust
binary, no broker, and no second process:

```json
{
  "providers": [
    {
      "id": "geph-prov",
      "provider": "geph",
      "pool_id": "geph-pool",
      "config": {
        "embedded_exit": { "allow_loopback": true },
        "secret": "any-value-here"
      }
    }
  ]
}
```

The object form carries the knobs:

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:0` | c2e listener address; the default picks an ephemeral loopback port. |
| `allow_loopback` | `false` | Permit loopback targets. The Rust exit (and the Go port by default) refuse non-globally-routable targets; this escape hatch is for single-box setups where the "internet" the exit reaches is a local server. |
| `seed_hex` | random per boot | 64 hex chars pinning the exit's ed25519 signing seed, so the exit's pubkey is stable across restarts. |

Credentials are not verified in this mode (the embedded exit has no broker,
exactly like a broker-less Rust exit), so `secret` can be any string; a fresh
signing key is generated per boot unless `seed_hex` pins one. The engine-level
proof is `goose`'s `TestE2E_GephProviderStandalone` and the plugin-level proof
is `TestGephProviderStandalone` here — both run in the default test suites
with no external dependencies.

## Wiring into goose

The plugin is bundled with goose (blank-imported by
[`include/register.go`](../../goose/include/register.go)), pulled in via a
`require` + `replace` in goose's `go.mod`:

```
require github.com/geph-official/geph5-go v0.0.0
replace github.com/geph-official/geph5-go => ../geph5-go
```

A goose config using it:

```json
{
  "inbounds": [
    { "id": "in-socks", "protocol": "socks5", "listen": "127.0.0.1:11080" }
  ],
  "providers": [
    {
      "id": "geph-prov",
      "provider": "geph",
      "pool_id": "geph-pool",
      "config": {
        "exit_constraint": { "direct": "203.0.113.7:9000/3b1a...pubhex" },
        "secret": "user-secret"
      }
    }
  ]
}
```

Route an inbound whose policy selects the `geph-pool` pool and traffic flows
through the tunnels.

## Tests

Unit tests (`go test ./plugins/geph/`) cover config parsing and registration
with no network. The standalone test (`TestGephProviderStandalone`, no build
tag, part of the default suite) boots the provider with `embedded_exit` and
pushes HTTP — small + 192 KiB multi-frame responses — through the plugin's
SOCKS5 outbound into the embedded exit, all in one process.

The real-network test needs a **Rust geph5-exit binary** and is gated behind
the `geph_real` build tag:

```bash
GEPH_EXIT_BIN=/path/to/geph5/bin-out/geph5-exit \
GEPH_TEST_TARGET=223.5.5.5:80 \
go test -tags geph_real -v ./plugins/geph/
```

It boots a real exit, connects the provider through the full handshake, and
pushes real HTTP through the tunnel (small + 192 KiB multi-frame responses to
a hermetic loopback target, plus a real-internet request when
`GEPH_TEST_TARGET` is set). The engine-level counterparts live in goose's
`test/e2e`: `geph_test.go` (real Rust exit, gated by `GEPH_EXIT_BIN`) and
`geph_standalone_test.go` (embedded exit, default suite).

Wire-protocol details (serde variant ordering, the metadata stream, exit
constraints) are in the module README's
[wire compatibility](../../README.md#wire-compatibility) section.
