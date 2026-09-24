package brokerproto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// AccountLevel mirrors geph5_broker_protocol::AccountLevel (snake_case).
type AccountLevel string

const (
	AccountLevelFree AccountLevel = "free"
	AccountLevelPlus AccountLevel = "plus"
)

// BwConsumptionInfo mirrors geph5_broker_protocol::BwConsumptionInfo.
type BwConsumptionInfo struct {
	MbUsed  uint32 `json:"mb_used"`
	MbLimit uint32 `json:"mb_limit"`
}

// UserInfo mirrors geph5_broker_protocol::UserInfo.
//   { user_id: u64, plus_expires_unix: Option<u64>, recurring: bool,
//     bw_consumption: Option<BwConsumptionInfo> }
type UserInfo struct {
	UserID          uint64              `json:"user_id"`
	PlusExpiresUnix *uint64             `json:"plus_expires_unix"`
	Recurring       bool                `json:"recurring"`
	BwConsumption   *BwConsumptionInfo  `json:"bw_consumption"`
}

// AuthError mirrors geph5_broker_protocol::AuthError (snake_case, externally
// tagged): "rate_limited" | "forbidden" | "wrong_level".
type AuthError string

const (
	AuthErrRateLimited AuthError = "rate_limited"
	AuthErrForbidden   AuthError = "forbidden"
	AuthErrWrongLevel  AuthError = "wrong_level"
)

func (e AuthError) Error() string { return "auth error: " + string(e) }

// ExitCategory mirrors ExitCategory (snake_case).
type ExitCategory string

const (
	ExitCategoryCore      ExitCategory = "core"
	ExitCategoryStreaming ExitCategory = "streaming"
)

// ExitDescriptor fully describes a particular exit.
// Rust: { c2e_listen: SocketAddr, b2e_listen: SocketAddr, country: CountryCode,
//         city: String, load: f32, expiry: u64 }
// SocketAddr serializes as "ip:port"; CountryCode serializes as the alpha2
// uppercase string (e.g. "US", "CA").
type ExitDescriptor struct {
	C2EListen string  `json:"c2e_listen"`
	B2EListen string  `json:"b2e_listen"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Load      float32 `json:"load"`
	Expiry    uint64  `json:"expiry"`
}

// ExitMetadata describes access policy for an exit.
type ExitMetadata struct {
	AllowedLevels []AccountLevel `json:"allowed_levels"`
	Category      ExitCategory   `json:"category"`
}

// ExitConstraint mirrors ExitConstraint (snake_case, externally tagged).
//   auto
//   { "direct": "host:port/pubkeyhex" }
//   { "hostname": "..." }
//   { "country": "US" }
//   { "country_city": ["US", "city"] }
type ExitConstraint struct {
	Kind        string
	Direct      string
	Hostname    string
	Country     string
	CountryCity []string // [country, city]
}

// AutoConstraint returns the default "auto" exit constraint.
func AutoConstraint() ExitConstraint { return ExitConstraint{Kind: "auto"} }

// MarshalJSON implements externally-tagged enum serialization.
func (c ExitConstraint) MarshalJSON() ([]byte, error) {
	switch c.Kind {
	case "auto":
		return json.Marshal("auto")
	case "direct":
		return json.Marshal(map[string]string{"direct": c.Direct})
	case "hostname":
		return json.Marshal(map[string]string{"hostname": c.Hostname})
	case "country":
		return json.Marshal(map[string]string{"country": c.Country})
	case "country_city":
		return json.Marshal(map[string][]string{"country_city": c.CountryCity})
	default:
		return nil, fmt.Errorf("brokerproto: unknown exit constraint kind %q", c.Kind)
	}
}

// UnmarshalJSON implements externally-tagged enum deserialization.
func (c *ExitConstraint) UnmarshalJSON(b []byte) error {
	// "auto" is a bare string.
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s != "auto" {
			return fmt.Errorf("brokerproto: bare exit constraint must be \"auto\", got %q", s)
		}
		c.Kind = "auto"
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for k, v := range m {
		switch k {
		case "direct":
			c.Kind = "direct"
			return json.Unmarshal(v, &c.Direct)
		case "hostname":
			c.Kind = "hostname"
			return json.Unmarshal(v, &c.Hostname)
		case "country":
			c.Kind = "country"
			return json.Unmarshal(v, &c.Country)
		case "country_city":
			c.Kind = "country_city"
			return json.Unmarshal(v, &c.CountryCity)
		default:
			return fmt.Errorf("brokerproto: unknown exit constraint variant %q", k)
		}
	}
	return fmt.Errorf("brokerproto: empty exit constraint object")
}

// ExitRouteDescriptor is { exit_pubkey: VerifyingKey, exit: ExitDescriptor,
// route: RouteDescriptor }. exit_pubkey is a 32-byte ed25519 VerifyingKey,
// which ed25519-dalek serializes as a JSON byte array ([u8; 32]).
type ExitRouteDescriptor struct {
	ExitPubkey []byte          `json:"exit_pubkey"` // 32 bytes, JSON array
	Exit       ExitDescriptor  `json:"exit"`
	Route      RouteDescriptor `json:"route"`
}

// ExitPubkeyHex returns exit_pubkey as a lowercase hex string, for comparison
// with hex-encoded keys in the client config (broker_keys.master etc.).
func (r ExitRouteDescriptor) ExitPubkeyHex() string { return hex.EncodeToString(r.ExitPubkey) }

// ExitList mirrors geph5_broker_protocol::ExitList:
//   { all_exits: Vec<(VerifyingKey, ExitDescriptor)>,
//     city_names: HashMap<String, HashMap<LanguageTag, String>> }
// all_exits is a JSON array of 2-element arrays [pubkey_bytes, exit_descriptor].
// city_names is a nested map (LanguageTag serializes as a BCP-47 string tag).
type ExitList struct {
	AllExits  []ExitListEntry            `json:"all_exits"`
	CityNames map[string]map[string]string `json:"city_names"`
}

// ExitListEntry is a single (VerifyingKey, ExitDescriptor) tuple, encoded as a
// 2-element JSON array [pubkey_bytes, exit_descriptor].
type ExitListEntry struct {
	Pubkey []byte         // 32 bytes, JSON array
	Exit   ExitDescriptor
}

func (e ExitListEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]json.RawMessage{
		mustJSON(e.Pubkey),
		mustJSON(e.Exit),
	})
}

func (e *ExitListEntry) UnmarshalJSON(b []byte) error {
	var arr [2]json.RawMessage
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	if err := json.Unmarshal(arr[0], &e.Pubkey); err != nil {
		return err
	}
	return json.Unmarshal(arr[1], &e.Exit)
}

// NetStatus is { exits: BTreeMap<String, (VerifyingKey, ExitDescriptor, ExitMetadata)> }.
// The map values are 3-element arrays [pubkey_bytes, exit, metadata].
type NetStatus struct {
	Exits map[string]NetStatusEntry `json:"exits"`
}

// NetStatusEntry is [pubkey_bytes, ExitDescriptor, ExitMetadata]. The pubkey is
// a VerifyingKey serialized as a JSON byte array ([u8; 32]).
type NetStatusEntry struct {
	Pubkey   []byte // 32 bytes, JSON array
	Exit     ExitDescriptor
	Metadata ExitMetadata
}

// PubkeyHex returns the pubkey as a lowercase hex string.
func (e NetStatusEntry) PubkeyHex() string { return hex.EncodeToString(e.Pubkey) }

// MarshalJSON encodes as a 3-element JSON array.
func (e NetStatusEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal([3]json.RawMessage{
		mustJSON(e.Pubkey),
		mustJSON(e.Exit),
		mustJSON(e.Metadata),
	})
}

// UnmarshalJSON decodes a 3-element JSON array.
func (e *NetStatusEntry) UnmarshalJSON(b []byte) error {
	var arr [3]json.RawMessage
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	if err := json.Unmarshal(arr[0], &e.Pubkey); err != nil {
		return err
	}
	if err := json.Unmarshal(arr[1], &e.Exit); err != nil {
		return err
	}
	return json.Unmarshal(arr[2], &e.Metadata)
}

func mustJSON(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}
