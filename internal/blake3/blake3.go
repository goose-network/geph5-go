// Package blake3 wraps github.com/zeebo/blake3 to expose the three modes
// used throughout geph5: plain hash, keyed_hash (MAC), and derive_key
// (contextual key derivation, matching Rust's blake3::derive_key).
package blake3

import (
	"github.com/zeebo/blake3"
)

// Hash returns the 32-byte BLAKE3 hash of data.
func Hash(data []byte) [32]byte {
	var out [32]byte
	h := blake3.New()
	h.Write(data)
	h.Sum(out[:0])
	return out
}

// HashBytes returns Hash(data) as a slice for convenience.
func HashBytes(data []byte) []byte {
	h := Hash(data)
	return h[:]
}

// KeyedHash returns the 32-byte BLAKE3 keyed hash (MAC) of data under the
// 32-byte key. Matches Rust blake3::keyed_hash(&key, data).
func KeyedHash(key [32]byte, data []byte) [32]byte {
	var out [32]byte
	h, err := blake3.NewKeyed(key[:])
	if err != nil {
		panic("blake3: invalid key length: " + err.Error())
	}
	h.Write(data)
	h.Sum(out[:0])
	return out
}

// DeriveKey derives a 32-byte subkey from a context string and key material,
// matching Rust blake3::derive_key(context, key_material). The context string
// is used as the mode's domain-separation tag (hashed once internally by
// BLAKE3's derive_key mode).
func DeriveKey(context string, keyMaterial []byte) [32]byte {
	var out [32]byte
	h := blake3.NewDeriveKey(context)
	h.Write(keyMaterial)
	h.Sum(out[:0])
	return out
}
