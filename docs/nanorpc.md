# nanorpc

Package `internal/nanorpc` is the Go port of the Rust `nanorpc` crate (v0.1.13)
plus the server side and sillad transport from `nanorpc-sillad`
(`libraries/nanorpc-sillad/src/lib.rs`). It implements the JSON-RPC 2.0 client
and server used by geph5, with a pluggable transport.

## Wire format

The transport is **newline-delimited JSON-RPC 2.0**, NOT length-prefixed. Each
request is a single JSON object terminated by `"\n"`; each response is a single
JSON object terminated by `"\n"`. A connection carries a sequential stream of
requests (one in flight at a time on the server side, matching the Rust
`BufReader` + split read/write loop).

```
request:  {"jsonrpc":"2.0","method":<str>,"params":[...],"id":<num|str>}
response: {"jsonrpc":"2.0","result":<any>,"id":<num|str>}
          {"jsonrpc":"2.0","error":{...},"id":<num|str>}
```

geph5's nanorpc uses externally-tagged params as a JSON array.

### JrpcID / id marshaling

Rust's `JrcId` is an **untagged** enum of `Number(i64)` or `String(String)`.
The default Rust client sends string ids like `"req-<random>"`. `JrpcID` in Go
stores the **raw JSON bytes** of the id verbatim so a Go server can echo a Rust
client's string id (and vice-versa) without interpreting it. The Go client
assigns **numeric** ids (monotonic from 1), which the Rust broker echoes back
unchanged. A zero `JrpcID` (empty `Raw`) represents an unset id and marshals as
`null`.

### Response marshaling

Rust's `JrpcResponse` has `result` and `error` as `Option<Value>` with
`skip_serializing_if = "Option::is_none"`: a SUCCESS response OMITS the
`error` key, and an ERROR response OMITS the `result` key. The Go struct
mirrors this with `omitempty` on `Result`/`Error` (a nil `Result`/`Error` is
omitted).

Rust's `JrcError` has `data: serde_json::Value` with **no** `skip_serializing_if`,
so `data` is ALWAYS present (serialized as `null` when `Value::Null`). The Go
`JrpcError` mirrors this by giving `Data` **no** `omitempty`; a nil
`json.RawMessage` marshals to `null`.

## Exported symbols

### Types

- `JrpcID` — `struct { Raw json.RawMessage }`. JSON-RPC id (number or string),
  stored as raw JSON bytes for verbatim echo.
  - `func (id JrpcID) IsZero() bool` — true if the id is unset (empty).
  - `func (id *JrpcID) SetNumber(n int64)` — assign a numeric id (bare JSON number).
  - `func (id JrpcID) MarshalJSON() ([]byte, error)` — render verbatim; unset -> `null`.
  - `func (id *JrpcID) UnmarshalJSON(b []byte) error` — capture raw id bytes (copies the buffer).

- `JrpcRequest` — `struct { JSONRPC string; Method string; Params json.RawMessage; ID JrpcID }`
  (json tags `jsonrpc`, `method`, `params`, `id`).

- `JrpcError` — `struct { Code int; Message string; Data json.RawMessage }`
  (json tags `code`, `message`, `data`). `Data` has **no** `omitempty` (always present, `null` when nil).

- `JrpcResponse` — `struct { JSONRPC string; Result json.RawMessage; Error *JrpcError; ID JrpcID }`.
  `Result` and `Error` have `omitempty` (success omits `error`, error omits `result`).

- `ServerError` — `struct { Code int; Message string; Data json.RawMessage }`.
  - `func (e *ServerError) Error() string` — `"nanorpc server error <code>: <message>"`.

- `Client` — `struct { transport RpcTransport; nextID atomic.Int64 }`. Assigns monotonic numeric ids.
  - `func NewClient(t RpcTransport) *Client` — wrap a transport; nextID starts at 1.
  - `func (c *Client) Call(ctx context.Context, method string, params json.RawMessage, out interface{}) error`
    — invoke a method, unmarshal `result` into `out`; a JSON-RPC error is returned as `*ServerError`.
  - `func (c *Client) CallRaw(ctx context.Context, req *JrpcRequest) (*JrpcResponse, error)`
    — low-level escape hatch; assigns ID and `jsonrpc:"2.0"` if unset, no result unwrapping.

- `DialerTransport` — `struct { Dialer sillad.Dialer }`. nanorpc `RpcTransport`
  backed by a sillad `Dialer`. Each `CallRaw` dials a **fresh** connection (no
  pooling, matching the Rust TODO), writes the JSON request + `"\n"`, reads one
  line back. Satisfies `RpcTransport`.
  - `func (t *DialerTransport) CallRaw(ctx context.Context, req *JrpcRequest) (*JrpcResponse, error)`

### Interfaces

- `RpcTransport` — `interface { CallRaw(ctx context.Context, req *JrpcRequest) (*JrpcResponse, error) }`.
- `RpcService` — `interface { RespondRaw(ctx context.Context, req *JrpcRequest) *JrpcResponse }`.
  Mirrors nanorpc's `RpcService::respond_raw`: the implementation switches on
  `req.Method`, produces the result/error, and echoes `req.ID`.

### Functions

- `func Serve(ctx context.Context, ln net.Listener, svc RpcService) error` —
  accept loop mirroring `nanorpc_sillad::rpc_serve`. Each accepted connection
  is handled in its own goroutine (tracked by a WaitGroup for structured
  concurrency); reads one JSON request per line, calls `svc.RespondRaw`, writes
  the JSON response + `"\n"`. Returns when the listener is closed (ctx
  cancellation closes the listener) or on a non-temporary Accept error.
  Per-connection: EOF/read error ends the loop; a malformed request ends the
  connection (no error response is sent, since the id cannot be reliably
  recovered); a nil response from the service is replaced with a `-32603`
  internal error echoing the request id; empty lines are skipped.

- `func EncodeParams(vs ...interface{}) (json.RawMessage, error)` — marshal a
  slice of values into the JSON array used as params; returns `"[]"` for no args.

## Rust counterpart

- Client types (`JrpcID`, `JrpcRequest`, `JrpcResponse`, `JrpcError`,
  `RpcTransport`, `Client`, `ServerError`, `EncodeParams`): Rust `nanorpc` crate v0.1.13.
- Server (`RpcService`, `Serve`) and `DialerTransport`: Rust `nanorpc-sillad`
  crate (`libraries/nanorpc-sillad/src/lib.rs`), specifically `rpc_serve` and
  `DialerTransport<D>`.

## Wire-compatibility notes

- Newline-delimited JSON-RPC, not length-prefixed. One request in flight per
  connection on the server side.
- `JrpcID` preserves the raw id bytes, so string ids from the Rust client are
  echoed verbatim and numeric ids from the Go client are echoed by the Rust
  broker unchanged.
- `JrpcResponse` omits `error` on success and `result` on error (matches Rust
  `skip_serializing_if = "Option::is_none"`).
- `JrpcError.Data` is always present (no `omitempty`), marshaling to `null`
  when nil (matches Rust `data: serde_json::Value` with no skip).
- `DialerTransport` opens a new connection per call (no pooling), matching the
  Rust implementation's documented TODO.
