package brokerproto

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/geph-official/geph5-go/internal/nanorpc"
)

// BrokerClient wraps a nanorpc transport with typed broker protocol methods.
// Method names and param orders match geph5_broker_protocol::BrokerProtocol.
type BrokerClient struct {
	rpc *nanorpc.Client
}

// NewBrokerClient wraps a transport.
func NewBrokerClient(t nanorpc.RpcTransport) *BrokerClient {
	return &BrokerClient{rpc: nanorpc.NewClient(t)}
}

// GetExitRouteArgs mirrors GetExitRouteArgs.
type GetExitRouteArgs struct {
	Token           json.RawMessage   `json:"token"`
	Sig             json.RawMessage   `json:"sig"`
	ExitConstraint  ExitConstraint    `json:"exit_constraint"`
	ClientMetadata  json.RawMessage   `json:"client_metadata"`
}

// GetExitRoute calls broker.get_exit_route, returning a signed ExitRouteDescriptor.
// The server returns { "Ok": JsonSigned<ExitRouteDescriptor> } | { "Err": GenericError }.
// nanorpc maps Result<T, E> to a response where result is ["Ok", value] or ["Err", err].
func (c *BrokerClient) GetExitRoute(ctx context.Context, args GetExitRouteArgs) (*JsonSigned, error) {
	params, err := json.Marshal([]interface{}{args})
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := c.rpc.Call(ctx, "get_exit_route", params, &raw); err != nil {
		return nil, err
	}
	return unwrapResult(raw, func(v json.RawMessage) (*JsonSigned, error) {
		var signed JsonSigned
		if err := json.Unmarshal(v, &signed); err != nil {
			return nil, err
		}
		return &signed, nil
	})
}

// GetNetStatus calls broker.get_net_status.
func (c *BrokerClient) GetNetStatus(ctx context.Context) (*JsonSigned, error) {
	params, _ := nanorpc.EncodeParams()
	var raw json.RawMessage
	if err := c.rpc.Call(ctx, "get_net_status", params, &raw); err != nil {
		return nil, err
	}
	return unwrapResult(raw, func(v json.RawMessage) (*JsonSigned, error) {
		var signed JsonSigned
		if err := json.Unmarshal(v, &signed); err != nil {
			return nil, err
		}
		return &signed, nil
	})
}

// GetMizaruSubkey calls broker.get_mizaru_subkey(level, epoch) -> Bytes.
// The result is a hex-encoded byte string (serde Bytes -> array of u8, which
// serde_json serializes as a sequence of numbers OR a base64 string depending
// on the Bytes serializer). geph5 uses `bytes::Bytes` which serializes as a
// sequence of bytes (array of u8) under serde_json by default.
func (c *BrokerClient) GetMizaruSubkey(ctx context.Context, level AccountLevel, epoch uint16) ([]byte, error) {
	params, _ := json.Marshal([]interface{}{level, epoch})
	var raw json.RawMessage
	if err := c.rpc.Call(ctx, "get_mizaru_subkey", params, &raw); err != nil {
		return nil, err
	}
	return unwrapResult(raw, func(v json.RawMessage) ([]byte, error) {
		return decodeBytes(v)
	})
}

// GetConnectTokenArgs mirrors the get_connect_token params.
type GetConnectTokenArgs struct {
	AuthToken  string          `json:"auth_token"`
	Level      AccountLevel    `json:"level"`
	Epoch      uint16          `json:"epoch"`
	BlindToken json.RawMessage `json:"blind_token"`
}

// GetConnectToken calls broker.get_connect_token -> BlindedSignature.
func (c *BrokerClient) GetConnectToken(ctx context.Context, args GetConnectTokenArgs) (json.RawMessage, error) {
	params, _ := json.Marshal([]interface{}{args})
	var raw json.RawMessage
	if err := c.rpc.Call(ctx, "get_connect_token", params, &raw); err != nil {
		return nil, err
	}
	return unwrapResultRaw(raw)
}

// GetUserInfo calls broker.get_user_info(auth_token) -> Option<UserInfo>.
// The broker returns Result<Option<UserInfo>, AuthError>; nanorpc maps the
// Err(AuthError) arm to a JSON-RPC error and the Ok(Option<UserInfo>) arm to
// the result field, which is null for None or the UserInfo object for Some.
func (c *BrokerClient) GetUserInfo(ctx context.Context, authToken string) (*UserInfo, error) {
	params, _ := json.Marshal([]interface{}{authToken})
	var raw json.RawMessage
	if err := c.rpc.Call(ctx, "get_user_info", params, &raw); err != nil {
		return nil, err
	}
	return unwrapResult(raw, func(v json.RawMessage) (*UserInfo, error) {
		if len(v) == 0 || string(v) == "null" {
			return nil, nil
		}
		var info UserInfo
		if err := json.Unmarshal(v, &info); err != nil {
			return nil, err
		}
		return &info, nil
	})
}

// CallRaw forwards a raw JSON-RPC request to the broker transport, returning
// the raw response. It is used by the control protocol's broker_rpc method to
// proxy arbitrary broker calls (e.g. opaque_abtest) without a typed wrapper.
// Unlike the typed methods, it does NOT unwrap a Result<...>; the caller gets
// the response exactly as the broker transport returned it (result field is
// the Ok value, error field set on Err).
func (c *BrokerClient) CallRaw(ctx context.Context, method string, params json.RawMessage) (*nanorpc.JrpcResponse, error) {
	req := &nanorpc.JrpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}
	return c.rpc.CallRaw(ctx, req)
}

// GetAuthToken calls broker.get_auth_token(credential) -> String.
func (c *BrokerClient) GetAuthToken(ctx context.Context, credential json.RawMessage) (string, error) {
	params, _ := json.Marshal([]interface{}{credential})
	var raw json.RawMessage
	if err := c.rpc.Call(ctx, "get_auth_token", params, &raw); err != nil {
		return "", err
	}
	var token string
	return token, unwrapResultInto(raw, &token)
}

// GetBwToken calls broker.get_bw_token(auth_token, blind_token) ->
// SingleBlindedSignature. The blinded token is a BlindedClientToken, which
// serde serializes as a byte array (array of ints); pass it as a
// json.RawMessage already encoded that way. The result SingleBlindedSignature
// is returned as raw JSON for the caller to unmarshal into mizaru2's type.
func (c *BrokerClient) GetBwToken(ctx context.Context, authToken string, blindToken json.RawMessage) (json.RawMessage, error) {
	params, _ := json.Marshal([]interface{}{authToken, blindToken})
	var raw json.RawMessage
	if err := c.rpc.Call(ctx, "get_bw_token", params, &raw); err != nil {
		return nil, err
	}
	return unwrapResultRaw(raw)
}

// GetPuzzle calls broker.get_puzzle() -> (String, u16). Unlike the Result-
// returning methods, get_puzzle returns the tuple directly as the result.
func (c *BrokerClient) GetPuzzle(ctx context.Context) (puzzle string, difficulty uint16, err error) {
	params, _ := nanorpc.EncodeParams()
	var raw json.RawMessage
	if err := c.rpc.Call(ctx, "get_puzzle", params, &raw); err != nil {
		return "", 0, err
	}
	var tuple [2]json.RawMessage
	if err := json.Unmarshal(raw, &tuple); err != nil {
		return "", 0, fmt.Errorf("brokerproto: decode puzzle tuple: %w", err)
	}
	if err := json.Unmarshal(tuple[0], &puzzle); err != nil {
		return "", 0, fmt.Errorf("brokerproto: decode puzzle string: %w", err)
	}
	if err := json.Unmarshal(tuple[1], &difficulty); err != nil {
		return "", 0, fmt.Errorf("brokerproto: decode puzzle difficulty: %w", err)
	}
	return puzzle, difficulty, nil
}

// RegisterUserSecret calls broker.register_user_secret(puzzle, solution) ->
// Result<String, GenericError>. Returns the registered secret string.
func (c *BrokerClient) RegisterUserSecret(ctx context.Context, puzzle, solution string) (string, error) {
	params, _ := json.Marshal([]interface{}{puzzle, solution})
	var raw json.RawMessage
	if err := c.rpc.Call(ctx, "register_user_secret", params, &raw); err != nil {
		return "", err
	}
	var secret string
	return secret, unwrapResultInto(raw, &secret)
}

// OpaqueAbTest calls broker.opaque_abtest(test, id) -> bool. Returns the
// A/B test bucket assignment directly (no Result wrapper).
func (c *BrokerClient) OpaqueAbTest(ctx context.Context, test string, id uint64) (bool, error) {
	params, _ := json.Marshal([]interface{}{test, id})
	var raw json.RawMessage
	if err := c.rpc.Call(ctx, "opaque_abtest", params, &raw); err != nil {
		return false, err
	}
	var result bool
	if err := json.Unmarshal(raw, &result); err != nil {
		return false, fmt.Errorf("brokerproto: decode abtest bool: %w", err)
	}
	return result, nil
}

// unwrapResult handles nanorpc's encoding of Result<T, E>. The geph5 broker
// returns Result<T, GenericError> which nanorpc serializes as the raw T on
// success (the nanorpc_derive macro maps Result Ok to result and Err to a
// JSON-RPC error). So `raw` is already the Ok value, not a tagged enum.
func unwrapResult[T any](raw json.RawMessage, decode func(json.RawMessage) (T, error)) (T, error) {
	var zero T
	if len(raw) == 0 || string(raw) == "null" {
		return zero, fmt.Errorf("brokerproto: empty result")
	}
	return decode(raw)
}

func unwrapResultRaw(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("brokerproto: empty result")
	}
	return raw, nil
}

func unwrapResultInto(raw json.RawMessage, out interface{}) error {
	if len(raw) == 0 || string(raw) == "null" {
		return fmt.Errorf("brokerproto: empty result")
	}
	return json.Unmarshal(raw, out)
}

// decodeBytes decodes a serde_json-serialized bytes::Bytes. geph5's Bytes
// serialize as an array of unsigned bytes (numbers 0..255) under the default
// serde_json serializer.
func decodeBytes(v json.RawMessage) ([]byte, error) {
	// Try array-of-numbers first (the common geph5 case).
	var arr []uint8
	if err := json.Unmarshal(v, &arr); err == nil {
		return arr, nil
	}
	// Fall back to a hex string.
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return hex.DecodeString(s)
	}
	return nil, fmt.Errorf("brokerproto: cannot decode bytes from %s", string(v))
}
