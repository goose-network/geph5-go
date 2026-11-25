// Package brokerproto implements the geph5 broker protocol types and the
// JsonSigned / StdcodeSigned signature envelopes, wire-compatible with the
// Rust geph5-broker-protocol crate.
//
// JSON serialization rules (matching serde + serde_json defaults):
//   - ed25519 VerifyingKey and Signature serialize as JSON arrays of bytes
//     (serde's serialize_bytes -> [u8; N] as a JSON array of integers), NOT
//     hex strings. ed25519-dalek 2.x uses serializer.serialize_bytes().
//   - SocketAddr serializes as a string "ip:port".
//   - Enums are externally tagged (serde default) unless noted.
//   - ExitConstraint, ExitCategory, AccountLevel use snake_case rename.
package brokerproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/goose-network/geph5-go/internal/blake3"
)

// VerifyError is returned by JsonSigned.Verify / StdcodeSigned.Verify.
type VerifyError string

const (
	ErrInvalidPublicKey  VerifyError = "invalid public key"
	ErrInvalidSignature  VerifyError = "invalid signature"
	ErrCannotDeserialize VerifyError = "could not deserialize interior value"
)

func (e VerifyError) Error() string { return string(e) }

// JsonSigned is a signed JSON value. The Rust struct is:
//
//   struct JsonSigned<T> {
//       inner_literal: String,   // serde_json::to_string(&inner)
//       signature: Signature,    // ed25519, JSON array of 64 bytes
//       pubkey: VerifyingKey,    // ed25519, JSON array of 32 bytes
//   }
//
// The signature is over blake3::keyed_hash(blake3::hash(domain), inner_literal_bytes).
// We keep inner_literal as the raw JSON string to preserve exact byte-for-byte
// signing semantics (the signature is over the *string*, not a re-serialized
// form, so we must not re-marshal before verifying).
//
// signature and pubkey are ed25519-dalek serialize_bytes output: JSON arrays of
// integers (0..255), NOT base64 strings. Go's encoding/json codec for []byte
// emits/expects base64, so we provide custom MarshalJSON/UnmarshalJSON using the
// integer-array wire form (accepting base64 on decode as a fallback). The live
// broker.geph.io get_net_status / get_exit_route responses confirm the
// integer-array encoding (pubkey: 32 ints, signature: 64 ints).
type JsonSigned struct {
	InnerLiteral string `json:"inner_literal"`
	Signature    []byte `json:"signature"` // 64 bytes, JSON array of ints
	Pubkey       []byte `json:"pubkey"`    // 32 bytes, JSON array of ints
}

// jsonSignedWire is the serde_json shape of JsonSigned<T>, with signature and
// pubkey kept as raw JSON so they can be decoded from integer arrays.
type jsonSignedWire struct {
	InnerLiteral string          `json:"inner_literal"`
	Signature    json.RawMessage `json:"signature"`
	Pubkey       json.RawMessage `json:"pubkey"`
}

// MarshalJSON encodes JsonSigned as serde_json would: signature and pubkey as
// JSON arrays of integers (ed25519-dalek serialize_bytes).
func (j JsonSigned) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonSignedWire{
		InnerLiteral: j.InnerLiteral,
		Signature:    encodeByteArray(j.Signature),
		Pubkey:       encodeByteArray(j.Pubkey),
	})
}

// UnmarshalJSON decodes JsonSigned from its serde_json form, accepting the
// integer-array byte encoding ed25519-dalek produces (and a base64 string as a
// defensive fallback).
func (j *JsonSigned) UnmarshalJSON(b []byte) error {
	var w jsonSignedWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	sig, err := decodeByteArray(w.Signature)
	if err != nil {
		return fmt.Errorf("brokerproto: JsonSigned.signature: %w", err)
	}
	pk, err := decodeByteArray(w.Pubkey)
	if err != nil {
		return fmt.Errorf("brokerproto: JsonSigned.pubkey: %w", err)
	}
	j.InnerLiteral = w.InnerLiteral
	j.Signature = sig
	j.Pubkey = pk
	return nil
}

// Verify checks the signature and, on success, unmarshals inner_literal into
// out. isValidPK is called on the decoded public key to confirm it is a
// trusted key (e.g. matches the configured broker master key).
func (j *JsonSigned) Verify(domain string, isValidPK func([32]byte) bool, out interface{}) error {
	if len(j.Pubkey) != 32 {
		return ErrInvalidPublicKey
	}
	var pkArr [32]byte
	copy(pkArr[:], j.Pubkey)
	if !isValidPK(pkArr) {
		return ErrInvalidPublicKey
	}
	if len(j.Signature) != 64 {
		return ErrInvalidSignature
	}
	domainHash := blake3.Hash([]byte(domain))
	toSign := blake3.KeyedHash(domainHash, []byte(j.InnerLiteral))
	if !ed25519.Verify(pkArr[:], toSign[:], j.Signature) {
		return ErrInvalidSignature
	}
	if err := json.Unmarshal([]byte(j.InnerLiteral), out); err != nil {
		return ErrCannotDeserialize
	}
	return nil
}

// PubkeyHex returns the pubkey as a lowercase hex string (for comparison with
// the configured broker_keys.master, which is hex).
func (j *JsonSigned) PubkeyHex() string { return hex.EncodeToString(j.Pubkey) }

// NewJsonSigned signs inner (as JSON) with seckey under the given domain.
// Used on the server side; included for completeness.
func NewJsonSigned(inner interface{}, domain string, seckey ed25519.PrivateKey) (*JsonSigned, error) {
	literal, err := json.Marshal(inner)
	if err != nil {
		return nil, err
	}
	domainHash := blake3.Hash([]byte(domain))
	toSign := blake3.KeyedHash(domainHash, literal)
	sig := ed25519.Sign(seckey, toSign[:])
	pub := seckey.Public().(ed25519.PublicKey)
	return &JsonSigned{
		InnerLiteral: string(literal),
		Signature:    sig,
		Pubkey:       pub,
	}, nil
}

// StdcodeSigned is the stdcode-based signed envelope:
//
//   struct StdcodeSigned<T> {
//       inner: T,
//       signature: Signature,   // JSON array of 64 bytes
//       pubkey: VerifyingKey,   // JSON array of 32 bytes
//   }
//
// The signature is over blake3::keyed_hash(blake3::hash(domain), inner.stdcode()).
// This envelope is used for ExitList (get_exits). It is stdcode-serialized
// on the wire (not JSON), so we expose the raw inner bytes for signing.
type StdcodeSigned struct {
	Inner     json.RawMessage `json:"inner"`
	Signature []byte          `json:"signature"`
	Pubkey    []byte          `json:"pubkey"`
}

// Sign domains used by geph5.
const (
	DomainExitDescriptor = "exit-descriptor"
	DomainNetStatus      = "net-status"
	DomainExitRoute      = "exit-route"
)

// stdcodeSignedWire is the serde_json shape of StdcodeSigned<T>, with signature
// and pubkey kept as raw JSON for integer-array decoding.
type stdcodeSignedWire struct {
	Inner     json.RawMessage `json:"inner"`
	Signature json.RawMessage `json:"signature"`
	Pubkey    json.RawMessage `json:"pubkey"`
}

// MarshalJSON encodes StdcodeSigned with signature/pubkey as integer arrays
// (ed25519-dalek serialize_bytes), matching serde_json.
func (s StdcodeSigned) MarshalJSON() ([]byte, error) {
	return json.Marshal(stdcodeSignedWire{
		Inner:     s.Inner,
		Signature: encodeByteArray(s.Signature),
		Pubkey:    encodeByteArray(s.Pubkey),
	})
}

// UnmarshalJSON decodes StdcodeSigned, accepting integer-array (or base64)
// signature/pubkey.
func (s *StdcodeSigned) UnmarshalJSON(b []byte) error {
	var w stdcodeSignedWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	sig, err := decodeByteArray(w.Signature)
	if err != nil {
		return fmt.Errorf("brokerproto: StdcodeSigned.signature: %w", err)
	}
	pk, err := decodeByteArray(w.Pubkey)
	if err != nil {
		return fmt.Errorf("brokerproto: StdcodeSigned.pubkey: %w", err)
	}
	s.Inner = w.Inner
	s.Signature = sig
	s.Pubkey = pk
	return nil
}

// encodeByteArray encodes b as a JSON array of integers (0..255), matching
// serde's serialize_bytes for ed25519 VerifyingKey / Signature.
func encodeByteArray(b []byte) json.RawMessage {
	arr := make([]uint16, len(b))
	for i, v := range b {
		arr[i] = uint16(v)
	}
	out, err := json.Marshal(arr)
	if err != nil {
		return json.RawMessage("null")
	}
	return out
}

// decodeByteArray decodes a serde serialize_bytes value: a JSON array of
// integers (the ed25519-dalek wire form), or a base64 string as a fallback.
func decodeByteArray(v json.RawMessage) ([]byte, error) {
	if len(v) == 0 || string(v) == "null" {
		return nil, nil
	}
	var arr []uint8
	if err := json.Unmarshal(v, &arr); err == nil {
		return arr, nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		if b, derr := base64.StdEncoding.DecodeString(s); derr == nil {
			return b, nil
		}
		return []byte(s), nil
	}
	return nil, fmt.Errorf("brokerproto: expected byte array, got %s", string(v))
}
