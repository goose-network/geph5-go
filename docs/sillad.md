# sillad

Package `internal/sillad` is the Go port of the Rust `sillad` dialer framework
(`libraries/sillad/src/lib.rs` and `libraries/sillad/src/dialer.rs`). It defines
the `Pipe` interface (a bidirectional byte stream with metadata) and the
`Dialer` interface (produces a `Pipe`), plus the combinators used by
geph5-client's route-to-dialer compiler: race, fallback, timeout, delay.

## Pipe

A `Pipe` is essentially a `net.Conn` augmented with protocol/remote-addr/shared-
secret metadata. It mirrors `sillad::Pipe` (Rust trait: `AsyncRead + AsyncWrite`
plus `protocol()`, `remote_addr()`, `shared_secret()`).

The `SharedSecret()` is used by the exit handshake to short-circuit X25519 when
the transport already established a shared secret (e.g. sosistab3 derives one
from X25519 during its own handshake).

## Exported symbols

### Interfaces

- `Pipe` — `interface { net.Conn; Protocol() string; RemoteAddrStr() string; SharedSecret() []byte }`.
  - `Protocol()` returns a short label like `"tcp"`, `"sosistab3"`, `"meeklike"`.
  - `RemoteAddrStr()` returns the remote address as a string, or `""` if unknown.
  - `SharedSecret()` returns the transport-level shared secret (e.g. the
    sosistab3 X25519 output), or `nil` if the transport has none. When present,
    the exit handshake uses a shared-secret challenge instead of X25519.

- `Dialer` — `interface { Dial(ctx context.Context) (Pipe, error) }`. Produces a `Pipe`.

### Dialer combinators (mirror `sillad::DialerExt`)

- `FailingDialer` — `struct { Err error }`. Always fails with `Err` (or a
  default `"sillad: failing dialer"` if `Err` is nil). Mirrors `sillad::FailingDialer`.
  - `func (d FailingDialer) Dial(ctx context.Context) (Pipe, error)`

- `DynDialer` — `struct { Func func(ctx context.Context) (Pipe, error) }`.
  Wraps a Dialer function for dynamic dispatch (mirrors `sillad::DynDialer`,
  the type-erased dialer).
  - `func (d DynDialer) Dial(ctx context.Context) (Pipe, error)` — calls `d.Func(ctx)`.

- `RaceDialer` — `struct { Inner []Dialer }`. Dials all inner dialers
  concurrently and returns the first successful `Pipe`, cancelling the rest.
  Mirrors `DialerExt::race`. Returns the first error if all fail.
  - `func (d RaceDialer) Dial(ctx context.Context) (Pipe, error)`

- `FallbackDialer` — `struct { Inner []Dialer }`. Dials inner dialers in order,
  returning the first success. Mirrors `DialerExt::fallback`.
  - `func (d FallbackDialer) Dial(ctx context.Context) (Pipe, error)`

- `TimeoutDialer` — `struct { Inner Dialer; Timeout time.Duration }`. Wraps a
  dialer with an overall deadline. Mirrors `DialerExt::timeout`.
  - `func (d TimeoutDialer) Dial(ctx context.Context) (Pipe, error)`

- `DelayDialer` — `struct { Inner Dialer; Delay time.Duration }`. Sleeps before
  dialing (respects ctx cancellation during the sleep). Mirrors `DialerExt::delay`.
  - `func (d DelayDialer) Dial(ctx context.Context) (Pipe, error)`

### Pipe implementation

- `ConnPipe` — `struct { net.Conn; ProtocolStr string; RemoteStr string; SharedSecretBytes []byte }`.
  Wraps a `net.Conn` to implement `Pipe` with the given protocol label.
  - `func (c *ConnPipe) Protocol() string` — returns `c.ProtocolStr`.
  - `func (c *ConnPipe) RemoteAddrStr() string` — returns `c.RemoteStr`, or
    `c.Conn.RemoteAddr().String()` if `RemoteStr` is empty, or `""`.
  - `func (c *ConnPipe) SharedSecret() []byte` — returns `c.SharedSecretBytes`.
  - Satisfies `Pipe` (compile-time asserted).

### Helpers

- `func ClosePipe(p Pipe)` — closes a pipe, tolerating nil.
- `func CopyN(dst io.Writer, src io.Reader, n int64) (int64, error)` — copies up
  to `n` bytes (wraps `io.CopyN`); used by the proxy loops.

## Rust counterpart

Rust `sillad` crate: `libraries/sillad/src/lib.rs` (`Pipe` trait, `DynDialer`,
`FailingDialer`) and `libraries/sillad/src/dialer.rs` (`DialerExt` with
`race`/`fallback`/`timeout`/`delay`/`dynamic`, `RaceDialer`, `FallbackDialer`,
`TimeoutDialer`, `DelayDialer`).

## Wire-compatibility notes

- `sillad` itself defines no wire format; it is a pure abstraction layer. Wire
  compatibility is the responsibility of concrete `Pipe`/`Dialer`
  implementations (e.g. `sosistab3`, `meeklike`, TCP).
- The `SharedSecret()` channel is the key cross-package contract: when a
  transport populates it, the exit handshake skips its own X25519 and uses a
  shared-secret challenge instead.
