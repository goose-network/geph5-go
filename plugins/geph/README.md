# geph — goose provider plugin

This package is the [goose](https://github.com/goose-network/goose) proxy-pool
engine's **geph provider plugin**: it embeds the geph5-go client core as a
library and exposes it to goose as a dynamic source of outbounds. Once the
embedded client has a live tunnel to a geph5 exit, the provider advertises one
`geph`-protocol outbound; a dial through it opens a tunnel stream **in
process** — the outbound calls the session manager's open-conn path directly —
so no SOCKS/HTTP hop exists between goose and the embedded client, and the
client binds no listener at all:

```
goose inbound ──▶ pool ──▶ "geph" outbound ──▶ OpenConn (in process, no listener)
                                            │
                        embedded geph5 client: session manager, 6 tunnels,
                        X25519+ed25519 handshake, picomux, sosistab3
                                            │
                              Rust geph5-exit ──▶ internet
```

The client's own TCP dials through **the engine**, split by role:

- **Broker fetches (control plane)** — the RPCs that retrieve the exit roster
  (`get_net_status`), auth tokens, and exit routes, including domain-fronted
  ones — ride the provider spec's `upstream_proxy` when it names a goose route
  (`outbound:`/`pool:`/`chain:`): the injected route dialer
  (`goose-plugin-api`'s `UpstreamDialer`) becomes
  `clientlib.Options.BrokerDialer`, so only the server-list fetches ride that
  outbound/pool/chain. Without a route they ride the engine stack dialer.
- **Exit dials (data path)** — the compiled route tree to the exit (sosistab3,
  plain TLS, meeklike, TCP hops), including every pinned per-exit client —
  **never** ride the provider upstream. They use the engine's stack dialer
  (`StackDialer` — layer 2/3/4, the system kernel stack or the gvisor
  netstack) as `clientlib.Options.StackDialer`, which threads it down to every
  TCP dialer in the route tree, or the system dialer when none is injected.

This is the provider-level `upstream_proxy` contract: it routes the plugin's
proxy-server-list fetches, not the outbounds' own traffic. (The separate
outbound-level `upstream_proxy` — an engine route injected per outbound spec —
is unrelated and unaffected.)

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
starts the client in a background goroutine from the factory and, independently
of session readiness, polls the broker's net status for the exit roster:

- `Outbounds()` advertises **one outbound per discovered exit** as soon as the
  roster is retrieved — the geph analogue of psiphon's datastore server list —
  and adds the general `geph` outbound once a live session exists. Per-exit
  ids are `<outbound_id>-<hostname>-<host:port>`: the exit's c2e address is
  part of the id so the server it pins is visible at a glance (the general
  outbound keeps its plain id — it rides a live session, not one server). Each
  change signals `Watch()` so the engine repolls promptly instead of waiting
  for the 2-minute fallback poll.
- A failed session (broker unreachable, exit down, or no credential) is retried
  indefinitely inside the session manager; the provider's only terminal error
  path is an invalid config (fails the factory), surfaced via `Outbounds()`. A
  credential-less zero-config client keeps the roster advertised in the
  `connecting` state rather than erroring out.

## Zero-config defaults

With no `config_path`, `embedded_exit`, or inline `exit_constraint`/`broker`,
the provider embeds the production geph5 network parameters — the `auto` exit
constraint, the direct broker `https://broker.geph.io`, and its verification
keys (`defaults.go`) — so it retrieves the live exit roster out of the box,
exactly as the psiphon plugin downloads its signed server list with no
operator-supplied file. Retrieving the roster (`get_net_status`) needs no
account; establishing a tunnel session does (geph is freemium — the production
broker rejects the `test_dummy` credential), so a `secret` (or other credential)
remains operator-supplied for traffic while the server list is discovered
zero-config.

## Config

The provider config is a JSON object whose keys overlap the geph5 client
config where they make sense as provider knobs:

```json
{
  "config_path":     "/path/to/geph5.yaml",
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
| `embedded_exit` | — | Standalone mode: boot the geph5 exit in-process (see below). `true` or `{ "listen", "allow_loopback", "seed_hex" }`. |
| `outbound_id` | `geph` | The goose outbound id the provider advertises; the `"geph"` outbound resolves its tunnel by this id at dial time. |
| `exit_constraint` | `auto` * | The client's exit constraint in its native enum shape: `"auto"`, `{"direct": "host:port/pubkeyhex"}`, `{"hostname": "..."}`, etc. |
| `credentials` | — | Full credential object, when a broker is used (`{"secret": ...}`, `"test_dummy"`, or `{"legacy_username_password": {...}}`). |
| `secret` | — | Shorthand for `credentials: {secret: ...}`. |
| `username` / `password` | — | Shorthand for the legacy credential. |
| `cache` | in-memory | Persistent client cache (routecache/auth) path. |
| `broker` | `https://broker.geph.io` * | Broker source: a bare URL string (direct) or a tagged object (`{"fronted": {...}}`). |
| `broker_keys` | embedded production keys * | Broker verification keys, required with a broker. |

\* These defaults apply only in the **zero-config** case (no `config_path`,
`embedded_exit`, or inline `exit_constraint`/`broker`); see
[Zero-config defaults](#zero-config-defaults). Any explicit mode is left untouched.

`config_path` loads a static YAML; the inline keys (when present) are applied on
top of it, so a shared YAML can be reused while the plugin overrides the exit
constraint.

Four shapes cover the common cases:

- **Zero-config (default)** — supply nothing (optionally a `secret` for traffic):
  the embedded production broker/keys and `auto` constraint retrieve and
  advertise the live exit roster out of the box, like psiphon.
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
[`include/register.go`](../../goose/include/register.go)), pulled in with a
plain `require` in goose's `go.mod` — the module is published at its repo,
so no `replace` is needed:

```
require github.com/goose-network/geph5-go v0.0.1
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

Unit tests (`go test ./plugins/geph/`) cover config parsing (including
stripping the engine-injected dialer keys), registration, and the in-memory
dial path (outbound → live provider → client) with no network. The standalone
test (`TestGephProviderStandalone`, no build tag, part of the default suite)
boots the provider with `embedded_exit` and pushes HTTP — small + 192 KiB
multi-frame responses — through the `"geph"` outbound's in-process dial into
the embedded exit, all in one process and with no listener anywhere in the
path.

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
