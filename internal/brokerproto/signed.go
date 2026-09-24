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
	"encoding/hex"
	"encoding/json"

	"github.com/geph-official/geph5-go/internal/blake3"
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
// signature and pubkey are JSON byte arrays (ed25519-dalek serialize_bytes).
// We model them as []byte so encoding/json marshals them as arrays of ints.
type JsonSigned struct {
	InnerLiteral string `json:"inner_literal"`
	Signature    []byte `json:"signature"` // 64 bytes, JSON array
	Pubkey       []byte `json:"pubkey"`    // 32 bytes, JSON array
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
