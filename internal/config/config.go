// Package config implements the geph5-client Config and its broker-source
// descriptors, wire-compatible with geph5_misc_rpc::client_config.
//
// Config can be loaded from YAML (the default-config.yaml format) or JSON.
// The YAML uses snake_case keys; BrokerSource is an externally-tagged enum
// (direct / fronted / direct_tcp / aws_lambda / race / priority_race).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/geph-official/geph5-go/internal/brokerproto"
)

// Config mirrors geph5_client::Config.
type Config struct {
	Socks5Listen      *string         `yaml:"socks5_listen" json:"socks5_listen"`
	HTTPProxyListen   *string         `yaml:"http_proxy_listen" json:"http_proxy_listen"`
	PACListen         *string         `yaml:"pac_listen" json:"pac_listen"`
	ControlListen     *string         `yaml:"control_listen" json:"control_listen"`
	ControlListenUnix *string         `yaml:"control_listen_unix" json:"control_listen_unix"`
	ControlListenPipe *string         `yaml:"control_listen_pipe" json:"control_listen_pipe"`
	ExitConstraint    brokerproto.ExitConstraint `yaml:"exit_constraint" json:"exit_constraint"`
	AllowDirect       bool            `yaml:"allow_direct" json:"allow_direct"`
	Cache             *string         `yaml:"cache" json:"cache"`
	Broker            *BrokerSource   `yaml:"broker" json:"broker"`
	TunneledBroker    *TunneledBrokerSource `yaml:"tunneled_broker" json:"tunneled_broker"`
	BrokerKeys        *BrokerKeys     `yaml:"broker_keys" json:"broker_keys"`
	PortForward       []PortForwardCfg `yaml:"port_forward" json:"port_forward"`
	SpoofDNS          bool            `yaml:"spoof_dns" json:"spoof_dns"`
	PassthroughChina  bool            `yaml:"passthrough_china" json:"passthrough_china"`
	AllowLAN          bool            `yaml:"allow_lan" json:"allow_lan"`
	DryRun            bool            `yaml:"dry_run" json:"dry_run"`
	Credentials       Credential      `yaml:"credentials" json:"credentials"`
	SessMetadata      json.RawMessage `yaml:"sess_metadata" json:"sess_metadata"`
	TaskLimit         *uint32         `yaml:"task_limit" json:"task_limit"`
}

// PortForwardCfg mirrors PortForwardCfg { listen: SocketAddr, connect: String }.
type PortForwardCfg struct {
	Listen  string `yaml:"listen" json:"listen"`
	Connect string `yaml:"connect" json:"connect"`
}

// BrokerKeys holds the broker verification keys in hex.
type BrokerKeys struct {
	Master     string `yaml:"master" json:"master"`
	MizaruFree string `yaml:"mizaru_free" json:"mizaru_free"`
	MizaruPlus string `yaml:"mizaru_plus" json:"mizaru_plus"`
	MizaruBw   string `yaml:"mizaru_bw" json:"mizaru_bw"`
}

// Credential mirrors geph5_broker_protocol::Credential (snake_case, externally tagged).
//   { "secret": "..." }
//   { "legacy_username_password": { "username": "...", "password": "..." } }
//   "test_dummy"
type Credential struct {
	Kind     string
	Secret   string
	Username string
	Password string
}

// MarshalJSON encodes the externally-tagged credential.
func (c Credential) MarshalJSON() ([]byte, error) {
	switch c.Kind {
	case "test_dummy", "":
		return json.Marshal("test_dummy")
	case "secret":
		return json.Marshal(map[string]string{"secret": c.Secret})
	case "legacy_username_password":
		return json.Marshal(map[string]map[string]string{
			"legacy_username_password": {"username": c.Username, "password": c.Password},
		})
	default:
		return nil, fmt.Errorf("config: unknown credential kind %q", c.Kind)
	}
}

// UnmarshalJSON decodes the externally-tagged credential.
func (c *Credential) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		c.Kind = s
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for k, v := range m {
		switch k {
		case "secret":
			c.Kind = "secret"
			return json.Unmarshal(v, &c.Secret)
		case "legacy_username_password":
			c.Kind = "legacy_username_password"
			var up struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.Unmarshal(v, &up); err != nil {
				return err
			}
			c.Username = up.Username
			c.Password = up.Password
			return nil
		default:
			return fmt.Errorf("config: unknown credential variant %q", k)
		}
	}
	return fmt.Errorf("config: empty credential")
}

// BrokerSource mirrors geph5_misc_rpc::BrokerSource (snake_case, externally tagged).
type BrokerSource struct {
	Kind        string // direct | fronted | direct_tcp | aws_lambda | race | priority_race
	Direct      string
	Fronted     *FrontedSource
	DirectTCP   string
	AwsLambda   *AwsLambdaSource
	Race        []BrokerSource
	PriorityRace []PriorityRaceEntry
}

// FrontedSource is the payload of the "fronted" variant.
type FrontedSource struct {
	Front       string   `yaml:"front" json:"front"`
	Host        string   `yaml:"host" json:"host"`
	OverrideDNS []string `yaml:"override_dns" json:"override_dns"`
}

// AwsLambdaSource is the payload of the "aws_lambda" variant.
type AwsLambdaSource struct {
	FunctionName string `yaml:"function_name" json:"function_name"`
	Region       string `yaml:"region" json:"region"`
	ObfsKey      string `yaml:"obfs_key" json:"obfs_key"`
}

// PriorityRaceEntry is one (priority, source) pair from the priority_race map.
type PriorityRaceEntry struct {
	Priority uint64
	Source   BrokerSource
}

// UnmarshalYAML decodes BrokerSource from YAML. The YAML shape is either a
// scalar (for direct), a map with a single variant key, or a sequence (race).
func (b *BrokerSource) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		b.Kind = "direct"
		b.Direct = value.Value
		return nil
	case yaml.SequenceNode:
		b.Kind = "race"
		b.Race = make([]BrokerSource, 0, len(value.Content))
		for _, n := range value.Content {
			var sub BrokerSource
			if err := n.Decode(&sub); err != nil {
				return err
			}
			b.Race = append(b.Race, sub)
		}
		return nil
	case yaml.MappingNode:
		// Single-key map: { <variant>: <payload> }
		if len(value.Content) != 2 {
			return fmt.Errorf("config: broker source map must have exactly one key, got %d", len(value.Content)/2)
		}
		key := value.Content[0].Value
		payload := value.Content[1]
		return b.decodeVariant(key, payload)
	}
	return fmt.Errorf("config: unexpected yaml node kind %d for broker source", value.Kind)
}

// UnmarshalJSON decodes BrokerSource from JSON. The JSON shape mirrors the
// YAML: a bare string (direct), an object with a single variant key, or an
// array (race). This matters because config.ParseYAML round-trips YAML
// through encoding/json, and embedders (e.g. the goose plugin) pass JSON
// config maps directly.
func (b *BrokerSource) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		b.Kind = "direct"
		b.Direct = s
		return nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err == nil {
		b.Kind = "race"
		b.Race = make([]BrokerSource, 0, len(arr))
		for _, item := range arr {
			var sub BrokerSource
			if err := json.Unmarshal(item, &sub); err != nil {
				return err
			}
			b.Race = append(b.Race, sub)
		}
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if len(m) != 1 {
		return fmt.Errorf("config: broker source map must have exactly one key, got %d", len(m))
	}
	for k, v := range m {
		// decodeVariant expects a yaml.Node; round-trip the JSON value through
		// YAML so the same variant-decoding code serves both decoders.
		var node yaml.Node
		var probe any
		if err := json.Unmarshal(v, &probe); err != nil {
			return err
		}
		rawYAML, err := yaml.Marshal(probe)
		if err != nil {
			return err
		}
		if err := yaml.Unmarshal(rawYAML, &node); err != nil {
			return err
		}
		return b.decodeVariant(k, &node)
	}
	return fmt.Errorf("config: empty broker source")
}

func (b *BrokerSource) decodeVariant(key string, payload *yaml.Node) error {
	switch key {
	case "direct":
		b.Kind = "direct"
		return payload.Decode(&b.Direct)
	case "fronted":
		b.Kind = "fronted"
		var f FrontedSource
		if err := payload.Decode(&f); err != nil {
			return err
		}
		b.Fronted = &f
		return nil
	case "direct_tcp":
		b.Kind = "direct_tcp"
		return payload.Decode(&b.DirectTCP)
	case "aws_lambda":
		b.Kind = "aws_lambda"
		var a AwsLambdaSource
		if err := payload.Decode(&a); err != nil {
			return err
		}
		b.AwsLambda = &a
		return nil
	case "race":
		b.Kind = "race"
		return payload.Decode(&b.Race)
	case "priority_race":
		b.Kind = "priority_race"
		// priority_race is a map: { <priority>: <BrokerSource>, ... }
		if payload.Kind != yaml.MappingNode {
			return fmt.Errorf("config: priority_race must be a map")
		}
		for i := 0; i < len(payload.Content); i += 2 {
			prioNode := payload.Content[i]
			srcNode := payload.Content[i+1]
			var prio uint64
			if err := prioNode.Decode(&prio); err != nil {
				return err
			}
			var src BrokerSource
			if err := srcNode.Decode(&src); err != nil {
				return err
			}
			b.PriorityRace = append(b.PriorityRace, PriorityRaceEntry{Priority: prio, Source: src})
		}
		return nil
	default:
		return fmt.Errorf("config: unknown broker source variant %q", key)
	}
}

// TunneledBrokerSource mirrors TunneledBrokerSource (snake_case, externally tagged).
type TunneledBrokerSource struct {
	Kind   string
	Direct string
}

// UnmarshalYAML decodes TunneledBrokerSource.
func (t *TunneledBrokerSource) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		t.Kind = "direct"
		t.Direct = value.Value
		return nil
	}
	if value.Kind == yaml.MappingNode && len(value.Content) == 2 {
		key := value.Content[0].Value
		switch key {
		case "direct":
			t.Kind = "direct"
			return value.Content[1].Decode(&t.Direct)
		}
	}
	return fmt.Errorf("config: unexpected tunneled_broker shape")
}

// LoadYAML reads and parses a YAML config file.
func LoadYAML(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return ParseYAML(data)
}

// ParseYAML parses YAML config bytes.
func ParseYAML(data []byte) (*Config, error) {
	// yaml.v3 lowercases map keys? No — it preserves case. But our ExitConstraint
	// and Credential need custom YAML decoding. yaml.v3 calls UnmarshalYAML on
	// types that implement yaml.Unmarshaler. ExitConstraint is from brokerproto
	// and only implements json. We decode via a YAML intermediate then re-encode
	// to JSON for the brokerproto types.
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	// Normalize: yaml.v3 parses the bare "auto" exit_constraint as a string,
	// and priority keys as ints. Convert to JSON and let struct tags handle it.
	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("config: re-encode: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(jsonBytes, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	// yaml.v3 may emit "exit_constraint":"auto" which ExitConstraint.UnmarshalJSON handles.
	return &cfg, nil
}

// String returns a short description for logging.
func (c *Config) String() string {
	parts := []string{}
	if c.Socks5Listen != nil {
		parts = append(parts, "socks5="+*c.Socks5Listen)
	}
	if c.HTTPProxyListen != nil {
		parts = append(parts, "http="+*c.HTTPProxyListen)
	}
	if c.Broker != nil {
		parts = append(parts, "broker="+c.Broker.Kind)
	}
	return "Config{" + strings.Join(parts, ", ") + "}"
}
