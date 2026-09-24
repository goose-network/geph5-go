# geph5-go internal package docs

Wire-format and API documentation for the Go ports of geph5's internal
packages. Each file documents one package: its purpose, the Rust crate it
ports, every exported symbol, and notable wire-compatibility details.

- [nanorpc.md](nanorpc.md) — JSON-RPC 2.0 client/server over a pluggable
  transport (newline-delimited JSON). Ports the Rust `nanorpc` crate (v0.1.13)
  and `nanorpc-sillad` (server side + `DialerTransport`).
- [sillad.md](sillad.md) — dialer framework: `Pipe`/`Dialer` interfaces and
  combinators (race, fallback, timeout, delay). Ports the Rust `sillad` crate.
- [picomux.md](picomux.md) — stream multiplexer over a reliable byte stream
  (8-byte LE frame header). Ports the Rust `picomux` crate (v0.3.1).
- [sosistab3.md](sosistab3.md) — obfuscation transport (X25519 handshake +
  ChaCha20Poly1305 record framing). Ports the Rust `sillad-sosistab3` crate
  (client side).
