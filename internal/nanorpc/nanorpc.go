// Package nanorpc implements the JSON-RPC 2.0 client used by geph5 (the
// `nanorpc` crate). Requests and responses are standard JSON-RPC 2.0
// objects:
//
//   request:  { "jsonrpc": "2.0", "method": <str>, "params": [...], "id": <num|str> }
//   response: { "jsonrpc": "2.0", "result": <any>, "id": <num|str> }
//              { "jsonrpc": "2.0", "error": {...}, "id": <num|str> }
//
// geph5's nanorpc uses externally-tagged params as a JSON array. The transport
// is pluggable (see RpcTransport).
//
// WIRE-COMPATIBILITY with the Rust `nanorpc` crate (v0.1.13):
//   - The request id (JrcId in Rust) is an UNTAGGED enum of Number(i64) or
//     String(String). The default Rust client sends STRING ids like
//     "req-<random>". JrpcID below preserves the raw JSON id bytes verbatim
//     so a Go server can echo a Rust client's string id (and vice-versa)
//     without interpreting it. The Go client assigns numeric ids, which the
//     Rust broker echoes back unchanged.
//   - Rust's JrpcResponse has `result` and `error` as Option<Value> with
//     skip_serializing_if = "Option::is_none": a SUCCESS response OMITS the
//     "error" key, and an ERROR response OMITS the "result" key. We mirror
//     this with omitempty on Result/Error (a nil Result/Error is omitted).
//   - Rust's JrcError has `data: serde_json::Value` with NO skip_serializing_if,
//     so "data" is ALWAYS present (serialized as null when Value::Null). We
//     mirror this by giving Data no omitempty; a nil json.RawMessage marshals
//     to null.
package nanorpc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
)

// JrpcID is a JSON-RPC request/response id that can be either a number or a
// string, mirroring Rust's untagged `JrcId { Number(i64), String(String) }`.
// It stores the raw JSON bytes of the id so it can be echoed verbatim by a
// server (preserving whatever form the client sent) and compared by the client.
// A zero JrpcID (empty Raw) represents an unset id.
type JrpcID struct {
	Raw json.RawMessage
}

// IsZero reports whether the id is unset (empty).
func (id JrpcID) IsZero() bool { return len(id.Raw) == 0 }

// SetNumber assigns a numeric id, marshaling it as a bare JSON number.
func (id *JrpcID) SetNumber(n int64) {
	b, _ := json.Marshal(n) // never errors for an int64
	id.Raw = b
}

// MarshalJSON renders the id verbatim. A zero (unset) id marshals as null,
// matching serde's serialization of an absent id in contexts that require a
// value.
func (id JrpcID) MarshalJSON() ([]byte, error) {
	if len(id.Raw) == 0 {
		return []byte("null"), nil
	}
	return id.Raw, nil
}

// UnmarshalJSON captures the raw id bytes verbatim (number or string).
func (id *JrpcID) UnmarshalJSON(b []byte) error {
	// json.Unmarshal validates b as a single JSON value and rejects trailing
	// data; copy b so the caller's buffer can be reused.
	cpy := make(json.RawMessage, len(b))
	copy(cpy, b)
	id.Raw = cpy
	return nil
}

// JrpcRequest is a JSON-RPC 2.0 request.
type JrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      JrpcID          `json:"id"`
}

// JrpcError is a JSON-RPC 2.0 error object. Note that Data has NO omitempty:
// mirroring Rust, the "data" field is always present (null when there is no
// structured data).
type JrpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// JrpcResponse is a JSON-RPC 2.0 response. Result and Error have omitempty so
// a success response omits "error" and an error response omits "result",
// matching Rust's skip_serializing_if = "Option::is_none".
type JrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JrpcError      `json:"error,omitempty"`
	ID      JrpcID          `json:"id"`
}

// RpcTransport sends a serialized JrpcRequest and returns the JrpcResponse.
type RpcTransport interface {
	CallRaw(ctx context.Context, req *JrpcRequest) (*JrpcResponse, error)
}

// Client is a nanorpc client over a transport. It assigns monotonic IDs.
type Client struct {
	transport RpcTransport
	nextID    atomic.Int64
}

// NewClient wraps a transport.
func NewClient(t RpcTransport) *Client {
	c := &Client{transport: t}
	c.nextID.Store(1)
	return c
}

// Call invokes a method with the given params (already JSON-encoded) and
// unmarshals the result into out. If the server returns a JSON-RPC error,
// it is returned as *ServerError.
func (c *Client) Call(ctx context.Context, method string, params json.RawMessage, out interface{}) error {
	req := &JrpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}
	req.ID.SetNumber(c.nextID.Add(1) - 1)
	resp, err := c.transport.CallRaw(ctx, req)
	if err != nil {
		return fmt.Errorf("nanorpc: transport error calling %q: %w", method, err)
	}
	if resp.Error != nil {
		return &ServerError{Code: resp.Error.Code, Message: resp.Error.Message, Data: resp.Error.Data}
	}
	if out != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return fmt.Errorf("nanorpc: cannot decode result of %q: %w", method, err)
		}
	}
	return nil
}

// ServerError is a JSON-RPC server-side error.
type ServerError struct {
	Code    int
	Message string
	Data    json.RawMessage
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("nanorpc server error %d: %s", e.Code, e.Message)
}

// CallRaw sends a raw JSON-RPC request over the transport and returns the
// response without any result unwrapping. It is the low-level escape hatch
// used by callers that need to forward arbitrary requests (e.g. the control
// protocol's broker_rpc). The request's ID is assigned here if unset.
func (c *Client) CallRaw(ctx context.Context, req *JrpcRequest) (*JrpcResponse, error) {
	if req.ID.IsZero() {
		req.ID.SetNumber(c.nextID.Add(1) - 1)
	}
	if req.JSONRPC == "" {
		req.JSONRPC = "2.0"
	}
	return c.transport.CallRaw(ctx, req)
}

// EncodeParams marshals a slice of values into the JSON array used as params.
func EncodeParams(vs ...interface{}) (json.RawMessage, error) {
	if len(vs) == 0 {
		return json.RawMessage("[]"), nil
	}
	return json.Marshal(vs)
}
