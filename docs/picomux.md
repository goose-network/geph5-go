# picomux

Package `internal/picomux` is the Go port of the Rust `picomux` crate (v0.3.1,
`libraries/picomux/src/lib.rs` and `libraries/picomux/src/frame.rs`). It
multiplexes many independent bidirectional streams over a single ordered,
reliable byte stream (e.g. a TCP connection or a sosistab3 pipe).

## Wire format

Each frame has an **8-byte header** followed by a body of `body_len` bytes:

```
 version:u8 | command:u8 | body_len:u16 LE | stream_id:u32 LE
```

The Rust `Header` is `#[repr(C)]` and serialized via `bytemuck::cast`, which on
a little-endian host yields native (little-endian) byte order. The Go port
writes the header with `binary.LittleEndian`, matching the Rust layout on LE
hosts (the only realistic deployment). `version` is always `1`.

### Commands

| Command | Value | Body | Meaning |
|---------|-------|------|---------|
| `CmdSYN`  | `0`    | metadata            | open a new stream |
| `CmdFIN`  | `1`    | none                | close the write direction of a stream |
| `CmdPSH`  | `2`    | payload             | push data |
| `CmdNOP`  | `3`    | none                | no-op |
| `CmdMORE` | `4`    | `u16 LE` quantum    | increase the peer's send window |
| `CmdPING` | `0xa0` | JSON `PingInfo`     | liveness probe |
| `CmdPONG` | `0xa1` | none                | liveness response (sent on stream 0) |

### Flow control

Each direction has a send window measured in **frames**. The receiver sends
`MORE` frames to increase the peer's window. Constants: `initWindow=10`,
`maxWindow=1500`, `mss=8192`, `maxBodyLen=65535`. The receiver tracks
`remote_window` (frames the peer may still send before getting a `MORE`) and
tops it up to `target_remote_window` (`MAX_WINDOW` by default; the Rust debloat
mode adjusts it based on a bandwidth estimate).

The Go port's `maybeSendMORE` is a **simplified** approximation: after each
`PSH` it sends a `MORE` of quantum `1` to keep the peer's window topped up.
This is conservative but correct for interop (the peer never stalls as long as
`MORE` keeps arriving); the exact quantum does not need to match the Rust BDP-
based quanta. The BDP-based window adjustment (`SetDebloat`) is **not
implemented**; `SetDebloat` is a no-op that merely records the flag for
interface compatibility with the session manager.

### Liveness

A `PING` is sent every `ping_interval`; if no `PONG` arrives within `timeout`,
the mux dies. The `PING` body is JSON `{"next_ping_in_ms":N}`. Default
(`DefaultLiveness`): 1800s ping interval, 30s timeout (matches Rust).

## Exported symbols

### Constants

- `CmdSYN uint8 = 0`, `CmdFIN uint8 = 1`, `CmdPSH uint8 = 2`, `CmdNOP uint8 = 3`,
  `CmdMORE uint8 = 4`, `CmdPING uint8 = 0xa0`, `CmdPONG uint8 = 0xa1`.

### Types

- `Header` — `struct { Version uint8; Command uint8; BodyLen uint16; StreamID uint32 }`.
  8-byte LE frame header (matches Rust `#[repr(C)]` `Header`).

- `PingInfo` — `struct { NextPingInMs uint32 }` (json tag `next_ping_in_ms`).
  JSON body of a `PING` frame.

- `LivenessConfig` — `struct { PingInterval time.Duration; Timeout time.Duration }`.
  - `func DefaultLiveness() LivenessConfig` — returns `{1800s, 30s}` (matches Rust default).

- `PicoMux` — `struct { ... }`. Multiplexes streams over a single connection.
  - `func New(conn net.Conn) *PicoMux` — wraps a connection (must be a reliable
    ordered byte stream); starts the read loop and ping loop; `alive=true`.
  - `func (pm *PicoMux) SetLiveness(lc LivenessConfig)` — update ping/pong config.
  - `func (pm *PicoMux) SetDebloat(on bool)` — no-op; records the debloat flag
    (BDP-based window adjustment not implemented).
  - `func (pm *PicoMux) IsAlive() bool` — whether the mux is still alive.
  - `func (pm *PicoMux) Close() error` — idempotent shutdown: marks dead, closes
    all streams, closes the underlying connection.
  - `func (pm *PicoMux) LastLatency() time.Duration` — last measured ping
    latency, or `-1` if none.
  - `func (pm *PicoMux) WaitUntilDead() error` — blocks until the mux dies,
    returns the error.
  - `func (pm *PicoMux) Open(metadata []byte) (*Stream, error)` — open a new
    stream to the peer with the given metadata; picks a random unused stream id
    and sends a `SYN` with the metadata as body.
  - `func (pm *PicoMux) Accept() (*Stream, error)` — wait for the peer to open a
    new stream (blocks; returns error if the mux dies).

- `Stream` — `struct { pm *PicoMux; state *streamState }`. A single multiplexed
  bidirectional stream implementing `net.Conn` semantics.
  - `func (s *Stream) Metadata() []byte` — metadata supplied at open/accept.
  - `func (s *Stream) Read(b []byte) (int, error)` — reads decrypted stream
    data; drains a per-stream leftover buffer first, then pulls the next `PSH`
    payload from the recv channel (returns `io.EOF` on `FIN`/close).
  - `func (s *Stream) Write(b []byte) (int, error)` — writes data, split into
    `MSS`-sized (`8192`) `PSH` frames; waits for a send-window permit (flow
    control) before each frame.
  - `func (s *Stream) Close() error` — closes the stream (sends `FIN` for the
    write direction); idempotent.
  - `func (s *Stream) LocalAddr() net.Addr` — delegates to the underlying conn.
  - `func (s *Stream) RemoteAddr() net.Addr` — delegates to the underlying conn.
  - `func (s *Stream) SetDeadline(t time.Time) error` — delegates to the underlying conn.
  - `func (s *Stream) SetReadDeadline(t time.Time) error` — delegates to the underlying conn.
  - `func (s *Stream) SetWriteDeadline(t time.Time) error` — delegates to the underlying conn.

## Rust counterpart

Rust `picomux` crate v0.3.1: `libraries/picomux/src/lib.rs` (multiplexer, read
loop, ping loop, flow control) and `libraries/picomux/src/frame.rs` (`Header`
`#[repr(C)]`, command constants `CMD_SYN`..`CMD_PONG`, `PingInfo`, `Frame::read`
/`Frame::bytes`).

## Wire-compatibility notes

- 8-byte LE header: `version:u8=1 | command:u8 | body_len:u16 LE | stream_id:u32 LE`.
  Matches Rust `#[repr(C)]` `Header` cast via `bytemuck` on LE hosts.
- Command values match exactly (`SYN=0, FIN=1, PSH=2, NOP=3, MORE=4, PING=0xa0, PONG=0xa1`).
- `MORE` body is a `u16 LE` quantum; the Go port sends quantum `1` per `PSH`
  (simplified but interop-correct; Rust sends BDP-based larger quanta).
- `PING` body is JSON `{"next_ping_in_ms":u32}`; `PONG` has empty body on stream 0.
- Stream ids are random `u32` (Go uses `rand.Uint32()`; Rust uses a similar
  random id strategy). A duplicate `SYN` for an existing stream id kills the mux.
- `SetDebloat` is a no-op stub (the Rust BDP-based `target_remote_window`
  adjustment is not ported); the flag is stored only for interface compatibility.
- `PSH` payloads are split at `MSS=8192`; `maxBodyLen=65535` (u16 cap).
- Half-close: `FIN` closes the write direction; the read side returns `EOF`
  after draining buffered payloads. (picomux 0.3.1 added independent stream
  half-close; this port models `FIN` as closing the inbound recv channel.)
