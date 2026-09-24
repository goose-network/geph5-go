# geph5-go

A Go port of the [geph5](https://github.com/geph-official/geph5) **client core**, byte-for-byte wire-compatible with the existing Rust broker and exits.

This is **not** a reimplementation of the broker or exit side — it speaks the same JSON-RPC, sosistab3/picomux framing, and ed25519-signed route formats as the Rust `geph5-client`, so a Go client connects to a Rust broker and through Rust exits transparently.

- **Module:** `github.com/geph-official/geph5-go`
- **Go version:** 1.27
- **Scope:** the client engine (`binaries/geph5-client` in the Rust workspace). ~14k LOC across 29 packages.
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
