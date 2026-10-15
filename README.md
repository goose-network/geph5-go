# geph5-go

A Go port of the [geph5](https://github.com/geph-official/geph5) **client core**, byte-for-byte wire-compatible with the existing Rust broker and exits.

This is **not** a reimplementation of the broker or exit side — it speaks the same JSON-RPC, sosistab3/picomux framing, and ed25519-signed route formats as the Rust `geph5-client`, so a Go client connects to a Rust broker and through Rust exits transparently. For single-process deployments, [`internal/exitlib`](#standalone-one-process-operation) also implements the **exit server** side in Go, so the client and the exit can run in one process with no Rust binary at all.

- **Module:** `github.com/geph-official/geph5-go`
- **Go version:** 1.27
- **Scope:** the client engine (`binaries/geph5-client` in the Rust workspace). ~14k LOC across 29 packages.
- **Also:** a provider plugin for the [goose](https://github.com/goose-network/goose) proxy-pool engine (`plugins/geph`) that embeds this client, proven against a real Rust exit with real traffic — and, via its `embedded_exit` option, against the Go exit in the same process.
- **Status:** `go build ./...`, `go vet ./...`, and `go test ./...` all pass clean.

## What is ported

All eight concurrent services from Rust's `client_main` (`binaries/geph5-client/src/client.rs`) are wired into `cmd/geph-client/main.go`:

| Service | Go package | Rust counterpart |
|---|---|---|
| SOCKS5 proxy | `internal/proxy/socks5` | `socks5_loop` |
| HTTP proxy | `internal/proxy/http` | `http_proxy_serve` |
| PAC file server | `internal/pac` | `pac_serve` |
| Port forwarding | `internal/portforward` | `port_forward` |
| VPN (userspace TCP/IP) | `internal/vpn` | `vpn_loop` |
| Auth / token refresh | `internal/auth` | `auth_loop` |
| Bandwidth-token refresh | `internal/bwtoken` | `bw_token_refresh_loop` |
| Control RPC (tcp/unix/pipe) | `internal/control` + `internal/nanorpc` | `rpc_serve` |

In `dry_run` mode, only the control RPC server runs — matching Rust exactly.

## Build & test

```bash
cd geph5-go
go build ./...
go vet ./...
go test ./...
```

### Real-network tests

Two end-to-end tests dial a **real Rust `geph5-exit`** and push real HTTP
through the full tunnel — the geph plugin here, and the goose engine that
loads it. They need the exit binary (built in the geph5 Rust workspace) and
are gated behind the `geph_real` build tag / `GEPH_EXIT_BIN` env var:

```bash
# plugin level (this repo): full handshake + HTTP through the tunnel
GEPH_EXIT_BIN=../geph5/bin-out/geph5-exit \
GEPH_TEST_TARGET=223.5.5.5:80 \
go test -tags geph_real -v ./plugins/geph/

# engine level (goose): provider provisioned via goose's REST API,
# pool fill, HTTP through inbound -> pool -> geph tunnel, metric recorded
cd ../goose
GEPH_EXIT_BIN=../geph5/bin-out/geph5-exit \
GEPH_TEST_TARGET=223.5.5.5:80 \
GOTOOLCHAIN=go1.26.8 go test -run TestE2E_Geph -v ./test/e2e/
```

`GEPH_TEST_TARGET` (optional) additionally pushes one request to a real
internet host through the tunnel; it must be an IP-literal `host:port` the
exit can reach.

### Standalone tests (no Rust binary)

Two further end-to-end tests run the **Go exit** (`internal/exitlib`) in the
same process as the client — no `geph5-exit` binary, no env vars, no second
process — and are part of the default `go test ./...`:

- `internal/exitlib` — a bare `clientlib` client tunnels through a Go exit:
  small + 192 KiB HTTP responses byte-exact, plus allow-rule negative tests
  (plain loopback refused; allowed with `AllowLoopback`).
- `plugins/geph` `TestGephProviderStandalone` — the goose provider in
  `embedded_exit` mode: plugin + client + exit in one process, HTTP and a
  192 KiB body through the provider's SOCKS5 outbound.

In goose, `test/e2e.TestE2E_GephProviderStandalone` proves the same at
engine level: admin-API-provisioned provider (embedded exit), pool fill,
HTTP through inbound → pool → tunnel → embedded exit → loopback target, and
the recorded metric — the entire chain in the test process.

> **gVisor version pin.** The VPN stack uses [`gvisor.dev/gvisor`](https://gvisor.dev) pinned to **`v0.0.0-20260218152508-eed1cebf761e`**. Later snapshots (e.g. `v0.0.0-20260924013400-27d5517ed85b`) carry a packaging defect where `bridge_test.go` declares `package bridge_test` inside the `stack` directory, which breaks `go build`. Do not upgrade gVisor without verifying the build.

## Running

```bash
go run ./cmd/geph-client --config config.yaml
```

Flags:

| Flag | Description |
|---|---|
| `--config <path>` | Path to a YAML config file (**required**). |
| `--stdio_vpn` | Use stdin/stdout as a VPN interface (16-bit big-endian length-prefixed raw IP packets). |
| `--vpn_fd <int>` | Wire an already-open platform-VPN file descriptor into the daemon (`-1` = none). Uses the same 16-bit BE framing. |

## Goose provider plugin

`plugins/geph` packages the client core as a **provider plugin** for the
[goose](https://github.com/goose-network/goose) proxy-pool engine: it embeds
the full client — auth loop, session manager with its 6 concurrent tunnels,
SOCKS5 listener — and once the first tunnel to a geph5 exit is live, advertises
one `socks5` outbound that goose merges into a managed pool. Any goose inbound
routed through that pool then forwards traffic through real geph5 tunnels. The
plugin imports only `goose-plugin-api` on the goose side (never goose itself),
preserving goose's plugin import boundary; it lives inside this module because
it embeds our `internal/` packages.

`internal/clientlib` is the embeddable bundle behind it and is usable directly,
with no goose involved:

```go
client, err := clientlib.Start(ctx, clientlib.Options{
    Socks5Listen: "127.0.0.1:0", // ephemeral loopback; the default
    Config:       cfg,           // must carry exit_constraint
})
addr := client.SocksAddr()       // bound address — valid from Start on
// client.SessionCount() > 0     // readiness: CONNECTs succeed from here on
```

The listener binds synchronously (bind errors fail `Start`); session
establishment proceeds in the background, so connections arriving before the
first session simply fail.

### Standalone (one-process) operation

`internal/exitlib` is the geph5 **exit server** as an embeddable library —
the c2e side of the protocol, mirroring the Rust `geph5-exit` serving path
(conntest echo → X25519+ed25519 handshake → ChaCha20Poly1305 records →
picomux → tunnel relay with the Rust allow rules). Paired with `clientlib`
the full client→tunnel→exit chain runs in one process, no Rust binary:

```go
exit, err := exitlib.Start(ctx, exitlib.Options{
    // C2EListen: "127.0.0.1:0" (default, ephemeral), Seed: zero = random
    // ed25519 seed, AllowLoopback: permit loopback targets (self-tests /
    // single-box deployments; the Rust exit always refuses them).
})
client, err := clientlib.Start(ctx, clientlib.Options{
    Config: &config.Config{ExitConstraint: brokerproto.ExitConstraint{
        Kind: "direct", Direct: exit.C2EAddr() + "/" + exit.PubkeyHex(),
    }},
})
```

Deviations from the Rust exit (invisible on the wire for the supported
paths): no b2e/broker listener, no credential verification (same as a
broker-less Rust exit), no DNS filtering, no IPv6 eyeballing, no UDP
tunnels; `AllowLoopback` is a Go-only escape hatch. The plugin's
`embedded_exit` option (see below) wraps exactly this for goose.

See [plugins/geph/README.md](plugins/geph/README.md) for the plugin's config
keys, bootstrap lifecycle, goose wiring, and the real-network test commands.

## Configuration

Config is loaded from YAML (`config.LoadYAML`) and mirrors `geph5_client::Config`. Keys are `snake_case`.

```yaml
socks5_listen: "127.0.0.1:9911"
http_proxy_listen: "127.0.0.1:9912"
pac_listen: "127.0.0.1:9913"
control_listen: "127.0.0.1:9914"
control_listen_unix: "/tmp/geph-control"
# control_listen_pipe: "geph-control"   # Windows only

cache: "/path/to/geph.db"        # omit for in-memory
dry_run: false
allow_direct: false
spoof_dns: false
passthrough_china: false
allow_lan: false

exit_constraint: auto            # or { "country": "US" }, { "id": 42 }, etc.

credentials:
  secret: "your-secret-token"
  # or:
  # legacy_username_password: { username: "...", password: "..." }
  # or the bare scalar: test_dummy

broker:                           # BrokerSource (externally-tagged enum)
  direct: "https://broker.example.com"
  # or fronted: { front: "...", host: "...", override_dns: [...] }
  # or a race list: [ direct: "...", fronted: {...} ]

broker_keys:
  master: "<hex ed25519 master pubkey>"
  mizaru_free: "<hex>"
  mizaru_plus: "<hex>"
  mizaru_bw: "<hex>"

port_forward:
  - listen: "127.0.0.1:8080"
    connect: "example.com:80"
```

### `BrokerSource` variants

`BrokerSource` is an externally-tagged enum (`geph5_misc_rpc::BrokerSource`). In YAML it is a scalar, a single-key map, or a sequence:

| Variant | YAML shape | Status |
|---|---|---|
| `direct` | `direct: "https://..."` (or bare scalar) | ✅ wired |
| `fronted` | `fronted: { front, host, override_dns }` | ✅ wired |
| `direct_tcp` | `direct_tcp: "host:port"` | ⚠️ returns "not yet implemented" |
| `aws_lambda` | `aws_lambda: { function_name, region, obfs_key }` | ⚠️ returns "not yet implemented" |
| `race` | a sequence of sources | ⚠️ returns "not yet implemented" |
| `priority_race` | `priority_race: { <priority>: <source>, ... }` | ⚠️ returns "not yet implemented" |

Only `direct` and `fronted` build a working transport today; the others fail fast so the caller knows to configure a supported source.

## Architecture

```
cmd/geph-client          entrypoint: flags, config, wires the 8 services
internal/
  config                 YAML/JSON config, BrokerSource/Credential enums
  nanorpc                JSON-RPC 2.0 client + server (wire-compat with Rust nanorpc)
  sillad                 Dialer/Pipe abstractions + dialer combinators
  brokerproto            broker client, signed routes, exit descriptors, net status
  routecache             persistent cached exit-route store
  database               key/value store backing the cache (file or in-memory)
  auth                   auth manager: credential -> auth token -> user info
  mizaru2                blind-RSA signature scheme (free/plus/bw token signing)
  bwtoken                blind bandwidth-token refresh + accounting
  session                session manager: combines route + dialer + exit handshake
  dialer                 route -> sillad.Dialer (direct, bound-tcp)
  exithandshake          client/exit X25519 handshake + encrypted pipe
  exitlib                embeddable geph5 exit server (standalone mode)
  sosistab3              obfuscated transport (cookie, handshake, state, pipe)
  picomux                stream multiplexer over a sillad.Pipe
  meeklike               meek-like datagram obfuscation (virta stream reassembly)
  hexdialer              hex-encoded pipe wrapper
  frontedhttp            domain-fronted HTTP nanorpc transport
  conntest               connectivity tester
  proxy/socks5           SOCKS5 server
  proxy/http             HTTP CONNECT proxy server
  pac                    PAC (proxy auto-config) file server
  portforward            local TCP port forwarding through the tunnel
  vpn                    gVisor userspace TCP/IP stack + stdio/fd VPN framing
  control                control RPC service (13 methods)
  tunnelcmd              tunnel command/response framing
  stdcode                bincode-compatible varint serialization
  blake3                 BLAKE3 hashing
  chacha20poly1305       ChaCha8-Poly1305 AEAD
  clientlib              embeddable client bundle (auth + sessions + SOCKS5)
  tools                  layer-isolated wire repro harnesses (pprobemux, psessmgr)
plugins/
  geph                   goose provider plugin embedding the client core
```

### Data path (how a SOCKS5 connection becomes a tunneled stream)

1. **SOCKS5** (`internal/proxy/socks5`) accepts a connection and resolves the target.
2. The session manager's `AsOpenConnFunc` (`internal/session`) is called with `tcp:<host:port>`.
3. `session.Manager` combines a cached **exit route** (`internal/routecache`, signed by the broker's ed25519 master key) with a **dialer** (`internal/dialer`) that establishes a `sillad.Pipe` to the exit.
4. The dialer stack layers obfuscation: `sosistab3` (`internal/sosistab3`) → `picomux` (`internal/picomux`) streams → `meeklike` (`internal/meeklike`) where applicable. The **exit handshake** (`internal/exithandshake`) performs an X25519 key exchange and wraps the pipe in ChaCha8-Poly1305 encryption.
5. Bytes are relayed bidirectionally through the encrypted `sillad.Pipe`.

### VPN path

`internal/vpn` builds a gVisor userspace TCP/IP stack (replacing Rust's `ipstack_geph`). Raw IP packets arrive via the `CaptureCh` (from `--stdio_vpn` or `--vpn_fd`, 16-bit **big-endian** length-prefixed). gVisor reassembles them into TCP/UDP streams; each stream is tunneled via the `OpenConnFunc` (the same session-manager path as SOCKS5). Return traffic is re-packetized and written to `InjectCh` with the same framing. UDP-over-tunnel uses a 2-byte **little-endian** u16 length prefix per datagram. A connection-refused dial error (`os error 111`) is translated into a TCP RST; other dial errors are dropped silently.

## Wire compatibility

This is the central design constraint. Every on-the-wire format matches the Rust implementation exactly.

### nanorpc (JSON-RPC 2.0)

Ported from the Rust `nanorpc` crate (v0.1.13). Transport is **newline-delimited** JSON-RPC (one JSON object per line), not length-prefixed. Each connection handles a sequential stream of requests.

- **Request id** (`JrcID`): Rust's `JrcId` is an `#[serde(untagged)]` enum of `Number(i64)` or `String(String)`. The Go `JrpcID` stores the raw JSON bytes verbatim so a server can echo a client's string id (e.g. `"req-<random>"`) without interpreting it. The Go client assigns numeric ids.
- **Response**: Rust's `JrpcResponse` has `result` and `error` as `Option<Value>` with `skip_serializing_if = "Option::is_none"` — a **success** response omits the `error` key, an **error** response omits the `result` key. Go mirrors this with `omitempty` on `Result`/`Error`.
- **Error `data`**: Rust's `JrcError.data` has **no** `skip_serializing_if`, so `data` is **always** present (serialized as `null` when there is no structured data). Go gives `Data` no `omitempty`; a nil `json.RawMessage` marshals to `null`.
- **Params**: always a JSON array.

### sosistab3 / picomux / meeklike

The obfuscated-transport and stream-multiplexing framing (`internal/sosistab3`, `internal/picomux`, `internal/meeklike`) is ported to produce byte-identical packets. `meeklike` includes the `virta` stream reassembly layer.

### stdcode

`internal/stdcode` is a Go implementation of Rust's **bincode** serialization as used by geph5 — specifically the **varint** encoding (not fixint), with a `u32` length prefix for sequences/strings. See the `stdcode` package docs and tests for the exact encoding. Do not "fix" the varint encoding to fixint; it is intentional and wire-compatible.

### Signed routes & net status

`internal/brokerproto` ports `JsonSigned` and `StdcodeSigned` — ed25519-signed JSON and stdcode payloads. Exit routes and net status are fetched from the broker, verified against the configured `broker_keys.master`, and cached.

## Control protocol

`internal/control` serves the `ControlProtocol` JSON-RPC service (the same one the `geph` daemon/CLI drives) over the tcp/unix/pipe listeners. Method names are `snake_case` (from `nanorpc_derive`); params are JSON arrays; `Result<T, String>`-returning methods encode the `Err` arm as a JSON-RPC error (code `-32000`, message = the string).

| Method | Params | Returns | Notes |
|---|---|---|---|
| `conn_info` | — | `ConnInfo` | `Disconnected` / `Connecting` / `Connected{sessions}` (externally tagged on `"state"`) |
| `stat_num` | `stat: string` | `f64` | Stubbed: returns `0.0` (no stats infra) |
| `start_time` | — | `u64` | Seconds since UNIX_EPOCH |
| `stop` | — | `null` | Stops the daemon after a 100ms delay |
| `recent_logs` | — | `Vec<String>` | Stubbed: returns `[]` (no DB log store) |
| `broker_rpc` | `method, params` | `Result<Value, String>` | Forwards an arbitrary broker call |
| `start_registration` | — | `Result<usize, String>` | Returns a registration id; **melpow solver not ported** (progress stays 0.0) |
| `poll_registration` | `idx: int` | `Result<RegistrationProgress, String>` | `{progress, secret}` |
| `stat_history` | `stat: string` | `Result<Vec<f64>, String>` | Only `"traffic"` valid; stubbed: returns `[]` |
| `net_status` | — | `Result<NetStatus, String>` | Fetches signed net status from broker |
| `latest_news` | `lang: string` | `Result<Vec<NewsItem>, String>` | Fetches update manifest; **minisign not verified** |
| `get_update_manifest` | — | `Result<[Value, String], String>` | `[manifest, url]` |
| `ab_test` | `key, secret` | `Result<bool, String>` | `id = u64::from_be_bytes(blake3(secret)[0..8])`, forwarded as `opaque_abtest` |

### Stubbed dependencies

A few Rust dependencies are intentionally stubbed with **wire-compatible return shapes** so the control protocol responds correctly even though the underlying feature is incomplete:

- **melpow puzzle solver** (`start_registration`): the registration goroutine logs a warning and leaves progress at `0.0` instead of solving.
- **minisign verification** (`latest_news`, `get_update_manifest`): the manifest is fetched and parsed but its signature is **not** verified.
- **SQLite log store** (`recent_logs`): returns an empty array.
- **TraffCount** (`stat_history`): returns an empty array.
- **fakedns** (VPN UDP port 53): stubbed.

These are the areas to fill in for a fully featured client.

## Broker client

`internal/brokerproto.BrokerClient` wraps a `nanorpc.RpcTransport` and exposes the broker RPCs:

- `GetExitRoute(ctx, GetExitRouteArgs)` → signed `ExitRouteDescriptor`
- `GetNetStatus(ctx)` → signed `NetStatus`
- `GetMizaruSubkey(ctx, level, epoch)` → subkey DER
- `GetConnectToken(ctx, GetConnectTokenArgs)` → connect token
- `GetUserInfo(ctx, authToken)` → `UserInfo`
- `GetAuthToken(ctx, credential)` → auth token string
- `GetBwToken(ctx, authToken, blindToken)` → blind-signed bw token
- `GetPuzzle(ctx)` → `(puzzle, difficulty)`
- `RegisterUserSecret(ctx, puzzle, solution)` → secret
- `OpaqueAbTest(ctx, test, id)` → `bool`
- `CallRaw(ctx, method, params)` → raw `JrpcResponse` (escape hatch)

## License

Same as the upstream geph5 project.
