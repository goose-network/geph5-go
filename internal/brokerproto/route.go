package brokerproto

import (
	"encoding/json"
	"fmt"
)

// RouteDescriptor mirrors geph5_broker_protocol::RouteDescriptor.
//
// serde representation (externally tagged, struct variants):
//
//   "tcp": "ip:port"                          (newtype variant)
//   { "sosistab3": { "cookie": str, "lower": <RouteDescriptor> } }
//   { "plain_tls": { "sni_domain": str|null, "lower": <RouteDescriptor> } }
//   { "race": [ <RouteDescriptor>, ... ] }
//   { "fallback": [ ... ] }
//   { "timeout": { "milliseconds": u32, "lower": <RouteDescriptor> } }
//   { "delay": { "milliseconds": u32, "lower": <RouteDescriptor> } }
//   { "conntest": { "ping_count": u32, "lower": <RouteDescriptor> } }
//   { "hex": { "lower": <RouteDescriptor> } }
//   { "meeklike": { "key": str, "cfg": <MeeklikeConfig>, "lower": <RouteDescriptor> } }
//   <any other JSON>                          (Other, untagged catch-all)
type RouteDescriptor struct {
	Kind string
	// Tcp variant: the "ip:port" string.
	TcpAddr string
	// Sosistab3 / PlainTls / Timeout / Delay / ConnTest / Hex / Meeklike share "lower".
	Lower *RouteDescriptor
	// Sosistab3 cookie.
	Cookie string
	// PlainTls SNI domain (nil = no SNI).
	SNIDomain *string
	// Race / Fallback: list of inner routes.
	Routes []RouteDescriptor
	// Timeout / Delay / ConnTest: millisecond / ping count scalar.
	Milliseconds uint32
	PingCount    uint32
	// Meeklike.
	MeeklikeKey string
	MeeklikeCfg MeeklikeConfig
	// Other: raw JSON for unknown variants.
	Other json.RawMessage
}

// MeeklikeConfig mirrors sillad_meeklike::MeeklikeConfig:
//
//	{ max_inflight: usize (default 50), mss: usize (default 3000), base64: bool (default false) }
//
// JSON tags match the Rust serde field names.
type MeeklikeConfig struct {
	MaxInflight int  `json:"max_inflight"`
	Mss         int  `json:"mss"`
	Base64      bool `json:"base64"`
}

// DefaultMeeklikeConfig returns the Rust Default for MeeklikeConfig.
func DefaultMeeklikeConfig() MeeklikeConfig {
	return MeeklikeConfig{MaxInflight: 50, Mss: 3000, Base64: false}
}

// MarshalJSON encodes the route tree with external tagging.
func (r RouteDescriptor) MarshalJSON() ([]byte, error) {
	switch r.Kind {
	case "tcp":
		return json.Marshal(r.TcpAddr)
	case "sosistab3":
		return json.Marshal(map[string]any{
			"sosistab3": map[string]any{"cookie": r.Cookie, "lower": r.Lower},
		})
	case "plain_tls":
		return json.Marshal(map[string]any{
			"plain_tls": map[string]any{"sni_domain": r.SNIDomain, "lower": r.Lower},
		})
	case "race":
		return json.Marshal(map[string]any{"race": r.Routes})
	case "fallback":
		return json.Marshal(map[string]any{"fallback": r.Routes})
	case "timeout":
		return json.Marshal(map[string]any{
			"timeout": map[string]any{"milliseconds": r.Milliseconds, "lower": r.Lower},
		})
	case "delay":
		return json.Marshal(map[string]any{
			"delay": map[string]any{"milliseconds": r.Milliseconds, "lower": r.Lower},
		})
	case "conntest":
		return json.Marshal(map[string]any{
			"conntest": map[string]any{"ping_count": r.PingCount, "lower": r.Lower},
		})
	case "hex":
		return json.Marshal(map[string]any{"hex": map[string]any{"lower": r.Lower}})
	case "meeklike":
		return json.Marshal(map[string]any{
			"meeklike": map[string]any{"key": r.MeeklikeKey, "cfg": r.MeeklikeCfg, "lower": r.Lower},
		})
	case "other", "":
		if len(r.Other) > 0 {
			return r.Other, nil
		}
		return json.Marshal(nil)
	default:
		return nil, fmt.Errorf("brokerproto: unknown route kind %q", r.Kind)
	}
}

// UnmarshalJSON decodes the externally-tagged route tree.
func (r *RouteDescriptor) UnmarshalJSON(b []byte) error {
	// "tcp" is a bare string newtype variant.
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		r.Kind = "tcp"
		r.TcpAddr = s
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		// Untagged Other catch-all.
		r.Kind = "other"
		r.Other = b
		return nil
	}
	for k, v := range m {
		switch k {
		case "tcp":
			r.Kind = "tcp"
			return json.Unmarshal(v, &r.TcpAddr)
		case "sosistab3":
			r.Kind = "sosistab3"
			return decodeLowerStruct(v, &r.Cookie, nil, &r.Lower)
		case "plain_tls":
			r.Kind = "plain_tls"
			return decodeLowerStruct(v, nil, &r.SNIDomain, &r.Lower)
		case "race":
			r.Kind = "race"
			return json.Unmarshal(v, &r.Routes)
		case "fallback":
			r.Kind = "fallback"
			return json.Unmarshal(v, &r.Routes)
		case "timeout":
			r.Kind = "timeout"
			return decodeMsStruct(v, &r.Milliseconds, &r.Lower)
		case "delay":
			r.Kind = "delay"
			return decodeMsStruct(v, &r.Milliseconds, &r.Lower)
		case "conntest":
			r.Kind = "conntest"
			return decodePingStruct(v, &r.PingCount, &r.Lower)
		case "hex":
			r.Kind = "hex"
			return decodeHexStruct(v, &r.Lower)
		case "meeklike":
			r.Kind = "meeklike"
			return decodeMeeklikeStruct(v, &r.MeeklikeKey, &r.MeeklikeCfg, &r.Lower)
		default:
			r.Kind = "other"
			r.Other = b
			return nil
		}
	}
	r.Kind = "other"
	r.Other = b
	return nil
}

func decodeLowerStruct(b []byte, cookie *string, sni **string, lower **RouteDescriptor) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	if cookie != nil {
		if v, ok := obj["cookie"]; ok {
			if err := json.Unmarshal(v, cookie); err != nil {
				return err
			}
		}
	}
	if sni != nil {
		if v, ok := obj["sni_domain"]; ok {
			var s *string
			if err := json.Unmarshal(v, &s); err != nil {
				return err
			}
			*sni = s
		}
	}
	if v, ok := obj["lower"]; ok {
		var inner RouteDescriptor
		if err := json.Unmarshal(v, &inner); err != nil {
			return err
		}
		*lower = &inner
	}
	return nil
}

func decodeMsStruct(b []byte, ms *uint32, lower **RouteDescriptor) error {
	var obj struct {
		Milliseconds uint32           `json:"milliseconds"`
		Lower        *RouteDescriptor `json:"lower"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	*ms = obj.Milliseconds
	*lower = obj.Lower
	return nil
}

func decodePingStruct(b []byte, pc *uint32, lower **RouteDescriptor) error {
	var obj struct {
		PingCount uint32           `json:"ping_count"`
		Lower     *RouteDescriptor `json:"lower"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	*pc = obj.PingCount
	*lower = obj.Lower
	return nil
}

func decodeHexStruct(b []byte, lower **RouteDescriptor) error {
	var obj struct {
		Lower *RouteDescriptor `json:"lower"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	*lower = obj.Lower
	return nil
}

func decodeMeeklikeStruct(b []byte, key *string, cfg *MeeklikeConfig, lower **RouteDescriptor) error {
	var obj struct {
		Key   string           `json:"key"`
		Cfg   MeeklikeConfig   `json:"cfg"`
		Lower *RouteDescriptor `json:"lower"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	*key = obj.Key
	*cfg = obj.Cfg
	*lower = obj.Lower
	return nil
}
