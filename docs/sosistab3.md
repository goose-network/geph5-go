# sosistab3

Package `internal/sosistab3` is the Go port of the Rust `sillad-sosistab3`
obfuscation transport (`libraries/sillad-sosistab3/src/lib.rs`,
`handshake.rs`, `state.rs`, `dialer.rs`, `listener.rs`). It is wire-compatible
with the Rust `sillad_sosistab3` crate and implements the `sillad.Pipe`
interface.

## Protocol overview

### 1. Handshake (client dialer side)

1. Generate an ephemeral X25519 keypair (clamping the secret key per RFC 7748).
2. Build a `Handshake{eph_pk, timestamp, padding_len, padding_hash,
   responding_to=blake3("")}` (112-byte plaintext).
3. Encrypt the handshake with the cookie key (ChaCha20Poly1305, 12-byte random
   nonce, AEAD over the 112-byte plaintext) -> **140 bytes** = `[12 nonce][112
   ciphertext][16 tag]`.
4. Send the 140-byte encrypted handshake followed by `padding_len` random
   padding bytes (`padding_len` is 0..=1024).
5. Read the server's 140-byte encrypted handshake, decrypt it, verify
   `responding_to == blake3(our_encrypted_handshake_bytes)`. Read and verify the
   server's padding (`padding_hash`).
6. Derive the shared secret = `X25519(our_eph_sk, their_eph_pk)`.

### 2. Record framing (`State`)

Two AEAD keys are derived via `blake3::derive_key`:
- client: `send="up"`, `recv="dn"`
- server: `send="dn"`, `recv="up"`

Each record is encrypted as:
```
[4 enc length][16 tag][N enc body][16 tag]
```
- The 4-byte **signed** LE `i32` length is encrypted with `send_nonce` (then
  `send_nonce+1` for the body) using ChaCha20Poly1305
  (`encrypt_in_place_detached`: ciphertext = plaintext XOR keystream, tag
  appended). A **negative** length (sign bit set) marks a **padding record**
  (discarded on decrypt).
- Nonces are 12 bytes: first 8 = `u64` LE counter (incremented by **2** per
  record: 0,1 for record 0; 2,3 for record 1; ...), last 4 = zero. Independent
  counters per direction.
- `obfs_lengths` (optional): pad short records (`< 2000` bytes) up to the next
  power of two plus `0..10` random bytes, emitted as padding (negative-length)
  records.

## Exported symbols

### Types

- `ObfsParams` — `struct { ObfsLengths bool; ObfsTiming bool }`. Matches Rust `ObfsParams`.

- `Cookie` — `struct { key [32]byte; params ObfsParams }`. The pre-shared
  obfuscation key, derived from a string.
  - `func NewCookie(s string) Cookie` — derives a cookie from a string of the
    form `"<key>---{json params}"` or just `"<key>"`. The key is derived via
    `blake3::derive_key("cookie", key)`. The optional JSON params
    (`{"obfs_lengths":bool,"obfs_timing":bool}`) are parsed best-effort.
  - `func (c Cookie) Params() ObfsParams` — returns the obfuscation parameters.
  - (unexported) `deriveKey(isServer bool) [32]byte` — `blake3::derive_key("client"|"server", key)`.

- `Handshake` — `struct { EphPK [32]byte; Timestamp uint64; PaddingLen uint64; PaddingHash [32]byte; RespondingTo [32]byte }`.
  The 112-byte plaintext handshake message. Serialized big-endian for the
  integer fields (matches Rust `Handshake::to_bytes`/`from_bytes` layout:
  `eph_pk[32] | timestamp:u64 | padding_len:u64 | padding_hash[32] | responding_to[32]`).

- `State` — `struct { sharedSecret []byte; sendAEAD cipher.AEAD; sendNonce uint64; recvAEAD cipher.AEAD; recvNonce uint64; obfs ObfsParams; sendBuf []byte }`.
  Per-direction AEAD state for an established pipe.
  - `func NewState(ss []byte, isServer bool, obfs ObfsParams) (*State, error)`
    — derives send/recv AEAD keys from the shared secret
    (`blake3::derive_key("up"|"dn", ss)`; server swaps up/dn).
  - `func (s *State) SharedSecret() []byte` — returns the shared secret bytes.
  - `func (s *State) Encrypt(data []byte, output *[]byte)` — encrypts a hunk of
    data, appending the ciphertext to `*output`. If `obfs.ObfsLengths` is set
    and the record is short (`< 2000`), padding records are added to reach
    `next_pow2(origLen+overhead) + rand(0..10)`.
  - `func (s *State) Decrypt(bts []byte, output *[]byte) (int, error)` —
    attempts to decrypt one record from `bts`, appending plaintext to `*output`.
    Returns the number of bytes consumed. Returns `errWouldBlock` if not enough
    data is present (caller waits for more); `errBrokenPipe` on AEAD failure or
    oversize length (`> 1 MiB`). Padding records (negative length) are
    decrypted but not appended to the output.

- `Pipe` — `struct { lower net.Conn; state *State; readBuf []byte; readClosed bool; rawReadBuf []byte; remote string }`.
  An established sosistab3 connection wrapping a lower sillad pipe. Implements
  `sillad.Pipe` and `net.Conn`.
  - `func Dial(lower net.Conn, cookie Cookie) (*Pipe, error)` — performs the
    client-side sosistab3 handshake over an already-connected lower pipe and
    returns an established `Pipe`. Generates the ephemeral X25519 keypair,
    sends encrypted handshake + padding, reads and verifies the server's
    handshake + padding, derives the shared secret, and constructs the `State`.
  - `func (p *Pipe) Protocol() string` — returns `"sosistab3"`.
  - `func (p *Pipe) RemoteAddrStr() string` — returns the remote address string
    (from the lower pipe's `RemoteAddrStr()` if available).
  - `func (p *Pipe) SharedSecret() []byte` — returns `p.state.SharedSecret()`
    (the X25519 output; used by the exit handshake to short-circuit X25519).
  - `func (p *Pipe) Read(b []byte) (int, error)` — reads and decrypts records
    from the lower pipe, buffering plaintext; returns `io.EOF` when the lower
    pipe closes and the buffer is drained.
  - `func (p *Pipe) Write(b []byte) (int, error)` — encrypts `b` and writes it
    to the lower pipe; returns `len(b)` on success.
  - `func (p *Pipe) Close() error` — closes the lower pipe.
  - `func (p *Pipe) LocalAddr() net.Addr` — delegates to the lower pipe.
  - `func (p *Pipe) RemoteAddr() net.Addr` — delegates to the lower pipe.
  - `func (p *Pipe) SetDeadline(t time.Time) error` — delegates to the lower pipe.
  - `func (p *Pipe) SetReadDeadline(t time.Time) error` — delegates to the lower pipe.
  - `func (p *Pipe) SetWriteDeadline(t time.Time) error` — delegates to the lower pipe.

## Rust counterpart

Rust `sillad-sosistab3` crate: `libraries/sillad-sosistab3/src/lib.rs`
(`Cookie`, `ObfsParams`, `NewCookie`), `handshake.rs` (`Handshake`,
`encrypt`/`decrypt`), `state.rs` (`State`, `encrypt`/`decrypt`, `derive_key`
labels `"up"`/`"dn"`), `dialer.rs` (client `Dial`), `listener.rs` (server side,
not ported to Go).

## Wire-compatibility notes

- Handshake ciphertext is exactly **140 bytes** = `[12 nonce][112 ciphertext][16 tag]`,
  followed by `padding_len` (0..=1024) random padding bytes. Matches Rust.
- `Handshake` plaintext layout (112 bytes, big-endian integers):
  `eph_pk[32] | timestamp:u64 BE | padding_len:u64 BE | padding_hash[32] | responding_to[32]`.
- Cookie key derivation: `blake3::derive_key("cookie", <key-string>)`.
  Per-direction handshake AEAD key: `blake3::derive_key("client"|"server", cookie.key)`.
- Record AEAD keys: `blake3::derive_key("up", ss)` and `blake3::derive_key("dn", ss)`
  (client sends with `"up"`, receives with `"dn"`; server swaps).
- Record format: `[4 enc length][16 tag][N enc body][16 tag]`. Length is a
  **signed** LE `i32`; negative = padding record (decrypted and discarded).
- Nonces: 12 bytes, `counter:u64 LE` in the first 8 bytes (incremented by **2**
  per record: length uses `nonce`, body uses `nonce+1`), last 4 bytes zero.
  Independent counters per direction.
- `obfs_lengths`: pads records `< 2000` bytes up to `next_pow2(len+overhead) + rand(0..10)`,
  emitted as padding (negative-length) records.
- The Go port implements the **client** (`Dial`) side only; the server
  (`listener`) side is not ported. `obfs_timing` is parsed and stored but has
  no effect (timing obfuscation is not implemented).
- `Pipe.SharedSecret()` exposes the X25519 output so the exit handshake can
  skip its own X25519 (the `sillad.Pipe.SharedSecret()` contract).
