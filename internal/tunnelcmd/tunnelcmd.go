// Package tunnelcmd ports geph5-misc-rpc::tunnel_command.
//
// The tunnel-open protocol works as follows: the client formats a
// TunnelCommand as its String() representation and passes those bytes as the
// picomux stream open() "protocol" argument. The exit parses it with
// ParseTunnelCommand, opens the requested tunnel, and (for "rich" commands)
// replies with write_prepend_length(serde_json(RichTunnelResponse)) — a 4-byte
// big-endian u32 length prefix followed by the JSON-encoded response.
package tunnelcmd

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// MaxPrependLength is the maximum message size accepted by
// read_prepend_length on the Rust side (100_000 bytes).
const MaxPrependLength = 100_000

// TunnelCommand mirrors the Rust enum TunnelCommand:
//
//	Legacy { protocol: String, host: String }
//	Rich(RichTunnelCommand)
//
// Legacy commands are formatted as "{protocol}${host}"; rich commands are
// formatted as the JSON serialization of RichTunnelCommand.
type TunnelCommand struct {
	// Kind is either "legacy" or "rich".
	Kind string
	// Protocol is the protocol string for both Legacy and Rich variants.
	Protocol string
	// Host is the host string for both Legacy and Rich variants.
	Host string
}

// Kinds for TunnelCommand.
const (
	KindLegacy = "legacy"
	KindRich   = "rich"
)

// RichTunnelCommand mirrors the Rust struct RichTunnelCommand
// { protocol: String, host: String } with snake_case JSON.
type RichTunnelCommand struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
}

// ProtocolOf returns the protocol of the command.
func (c TunnelCommand) ProtocolOf() string { return c.Protocol }

// HostOf returns the host of the command.
func (c TunnelCommand) HostOf() string { return c.Host }

// IsRich reports whether the command is the Rich variant.
func (c TunnelCommand) IsRich() bool { return c.Kind == KindRich }

// String implements fmt.Stringer, matching TunnelCommand's Display impl:
//
//   - Legacy -> "{protocol}${host}"
//   - Rich   -> serde_json::to_string(RichTunnelCommand)
//
// String never panics; a JSON marshal failure (impossible for this struct)
// falls back to the legacy formatting.
func (c TunnelCommand) String() string {
	switch c.Kind {
	case KindRich:
		b, err := json.Marshal(RichTunnelCommand{Protocol: c.Protocol, Host: c.Host})
		if err != nil {
			// json.Marshal of two strings cannot fail in practice; fall back
			// to a legacy-style representation to stay total.
			return fmt.Sprintf("%s$%s", c.Protocol, c.Host)
		}
		return string(b)
	default: // KindLegacy and any unknown kind.
		return fmt.Sprintf("%s$%s", c.Protocol, c.Host)
	}
}

// ParseTunnelCommand mirrors TunnelCommand's FromStr impl:
//
//   - if the input starts with '{', parse it as JSON RichTunnelCommand and
//     wrap in TunnelCommand::Rich;
//   - else if it contains '$', split once on the first '$' into
//     Legacy{protocol, host};
//   - else Legacy{protocol: "tcp", host: input}.
func ParseTunnelCommand(s string) (TunnelCommand, error) {
	if strings.HasPrefix(s, "{") {
		var rich RichTunnelCommand
		if err := json.Unmarshal([]byte(s), &rich); err != nil {
			return TunnelCommand{}, fmt.Errorf("failed to parse rich tunnel command: %w", err)
		}
		return TunnelCommand{Kind: KindRich, Protocol: rich.Protocol, Host: rich.Host}, nil
	}
	if idx := strings.IndexByte(s, '$'); idx >= 0 {
		return TunnelCommand{
			Kind:     KindLegacy,
			Protocol: s[:idx],
			Host:     s[idx+1:],
		}, nil
	}
	return TunnelCommand{Kind: KindLegacy, Protocol: "tcp", Host: s}, nil
}

// RichTunnelResponse mirrors the Rust enum RichTunnelResponse, a snake_case
// externally-tagged enum:
//
//	{ "success": { "resolved_addr": "ip:port", "open_ms": 123 } }   // open_ms may be null
//	{ "fail": "error message" }
//
// resolved_addr is a SocketAddr serialized as an "ip:port" string. open_ms is
// Option<u32>, serialized as a JSON number or null.
type RichTunnelResponse struct {
	// Kind is either "success" or "fail".
	Kind string
	// ResolvedAddr is the "ip:port" string for the Success variant.
	ResolvedAddr string
	// OpenMs is the optional open latency in milliseconds for the Success
	// variant. Nil means JSON null / Rust None.
	OpenMs *uint32
	// Fail is the error message for the Fail variant.
	Fail string
}

// Kinds for RichTunnelResponse.
const (
	KindSuccess = "success"
	KindFail    = "fail"
)

// SuccessResponse is a convenience constructor for the Success variant.
func SuccessResponse(resolvedAddr string, openMs *uint32) RichTunnelResponse {
	return RichTunnelResponse{Kind: KindSuccess, ResolvedAddr: resolvedAddr, OpenMs: openMs}
}

// FailResponse is a convenience constructor for the Fail variant.
func FailResponse(msg string) RichTunnelResponse {
	return RichTunnelResponse{Kind: KindFail, Fail: msg}
}

// successPayload is the inner object of the "success" variant.
type successPayload struct {
	ResolvedAddr string  `json:"resolved_addr"`
	OpenMs       *uint32 `json:"open_ms"`
}

// MarshalJSON implements externally-tagged, snake_case enum serialization
// matching serde's #[serde(rename_all = "snake_case")] default enum encoding.
func (r RichTunnelResponse) MarshalJSON() ([]byte, error) {
	switch r.Kind {
	case KindSuccess:
		return json.Marshal(map[string]successPayload{
			"success": {
				ResolvedAddr: r.ResolvedAddr,
				OpenMs:       r.OpenMs,
			},
		})
	case KindFail:
		return json.Marshal(map[string]string{"fail": r.Fail})
	default:
		return nil, fmt.Errorf("tunnelcmd: unknown RichTunnelResponse kind %q", r.Kind)
	}
}

// UnmarshalJSON implements externally-tagged, snake_case enum deserialization.
func (r *RichTunnelResponse) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for k, v := range m {
		switch k {
		case "success":
			var p successPayload
			if err := json.Unmarshal(v, &p); err != nil {
				return fmt.Errorf("tunnelcmd: invalid success payload: %w", err)
			}
			r.Kind = KindSuccess
			r.ResolvedAddr = p.ResolvedAddr
			r.OpenMs = p.OpenMs
			r.Fail = ""
			return nil
		case "fail":
			var msg string
			if err := json.Unmarshal(v, &msg); err != nil {
				return fmt.Errorf("tunnelcmd: invalid fail payload: %w", err)
			}
			r.Kind = KindFail
			r.Fail = msg
			r.ResolvedAddr = ""
			r.OpenMs = nil
			return nil
		default:
			return fmt.Errorf("tunnelcmd: unknown RichTunnelResponse variant %q", k)
		}
	}
	return fmt.Errorf("tunnelcmd: empty RichTunnelResponse object")
}

// ReadTunnelResponse reads a RichTunnelResponse from r using the
// read_prepend_length framing: a 4-byte big-endian u32 length prefix followed
// by that many bytes of JSON. Messages larger than MaxPrependLength
// (100_000) are rejected, matching the Rust implementation.
func ReadTunnelResponse(r io.Reader) (RichTunnelResponse, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return RichTunnelResponse{}, fmt.Errorf("tunnelcmd: reading response length: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > MaxPrependLength {
		return RichTunnelResponse{}, fmt.Errorf("tunnelcmd: response too large: %d > %d", n, MaxPrependLength)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return RichTunnelResponse{}, fmt.Errorf("tunnelcmd: reading response body: %w", err)
	}
	var resp RichTunnelResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		return RichTunnelResponse{}, fmt.Errorf("tunnelcmd: decoding response JSON: %w", err)
	}
	return resp, nil
}

// WriteTunnelResponse writes a RichTunnelResponse to w using the
// write_prepend_length framing: a 4-byte big-endian u32 length prefix followed
// by the JSON-encoded response. It is the inverse of ReadTunnelResponse and
// matches the Rust exit's write_prepend_length(&serde_json::to_vec(&resp)?).
func WriteTunnelResponse(w io.Writer, resp RichTunnelResponse) error {
	body, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("tunnelcmd: encoding response JSON: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("tunnelcmd: writing response length: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("tunnelcmd: writing response body: %w", err)
	}
	return nil
}
