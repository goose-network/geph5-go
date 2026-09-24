// Package meeklike implements the geph5 "meeklike" transport: a reliable
// stream (virta) layered over encrypted datagrams carried by HTTP POST
// request/response bodies.
//
// This is a Go port of the Rust crate sillad-meeklike (libraries/sillad-meeklike),
// together with a minimal port of the virta reliable-stream state machine
// (virta 0.1.2) that sillad-meeklike depends on.
//
// Wire compatibility:
//
//   - Datagram{ts:u64, stream_id:u128, inner:[]byte} is stdcode-serialized
//     (bincode varint), then encrypted with ChaCha8Poly1305 (8-round, NOT
//     20-round) using a PSK derived via blake3 keyed_hash. A 12-byte random
//     nonce is prepended to the ciphertext. The result is the HTTP POST body.
//   - PSK derivation: up_key = blake3::keyed_hash(b"-----------------meeklike-psk-up", material),
//     dn_key = blake3::keyed_hash(b"-----------------meeklike-psk-dn", material), where
//     material = blake3::hash(meeklike_key_string). The two context strings are
//     exactly 32 bytes (dashes + suffix).
//   - The HTTP backhaul POSTs to "/" with the encrypted datagram as the body
//     and receives an encrypted datagram as the response body. base64=false
//     means raw bytes (no base64 wrapping).
//   - max_inflight=50 concurrent POSTs, mss=3000 (max datagram payload).
package meeklike

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/geph-official/geph5-go/internal/blake3"
	"github.com/geph-official/geph5-go/internal/chacha20poly1305"
	"github.com/geph-official/geph5-go/internal/stdcode"
)

// pskContextUp is the 32-byte blake3 keyed_hash context for client->server
// (upstream) traffic. It is exactly b"-----------------meeklike-psk-up"
// (17 dashes + "meeklike-psk-up" = 32 bytes).
var pskContextUp = [32]byte{
	'-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-',
	'm', 'e', 'e', 'k', 'l', 'i', 'k', 'e', '-', 'p', 's', 'k', '-', 'u', 'p',
}

// pskContextDn is the 32-byte blake3 keyed_hash context for server->client
// (downstream) traffic. It is exactly b"-----------------meeklike-psk-dn"
// (17 dashes + "meeklike-psk-dn" = 32 bytes).
var pskContextDn = [32]byte{
	'-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-', '-',
	'm', 'e', 'e', 'k', 'l', 'i', 'k', 'e', '-', 'p', 's', 'k', '-', 'd', 'n',
}

// Datagram is the encrypted-datagram plaintext: a stdcode-serialized record
// carrying a timestamp, the 128-bit stream id, and the inner payload bytes.
//
// Rust: #[derive(Serialize, Deserialize)] pub struct Datagram { ts: u64,
// stream_id: u128, inner: Bytes }
type Datagram struct {
	Ts       uint64
	StreamID StreamID
	Inner    []byte
}

// StreamID is a 128-bit stream identifier, stored as high/low 64-bit halves.
type StreamID struct {
	Hi uint64
	Lo uint64
}

// RandomStreamID returns a cryptographically random 128-bit StreamID.
func RandomStreamID() StreamID {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return StreamID{
		Hi: binary.LittleEndian.Uint64(buf[:8]),
		Lo: binary.LittleEndian.Uint64(buf[8:]),
	}
}

// IsZero reports whether the StreamID is all zero.
func (s StreamID) IsZero() bool { return s.Hi == 0 && s.Lo == 0 }

// Equal reports whether two StreamIDs are equal.
func (s StreamID) Equal(o StreamID) bool { return s.Hi == o.Hi && s.Lo == o.Lo }

// MarshalStdcode encodes the Datagram using stdcode (bincode varint):
// ts:u64, stream_id:u128, inner:[]byte (u32 length prefix + bytes).
func (d *Datagram) MarshalStdcode() ([]byte, error) {
	enc := stdcode.NewEncoder()
	enc.EncodeU64(d.Ts)
	enc.EncodeU128(d.StreamID.Hi, d.StreamID.Lo)
	enc.EncodeBytes(d.Inner)
	return enc.Bytes(), nil
}

// UnmarshalStdcode decodes a stdcode-encoded Datagram.
func (d *Datagram) UnmarshalStdcode(b []byte) error {
	dec := stdcode.NewDecoder(b)
	ts, err := dec.DecodeU64()
	if err != nil {
		return fmt.Errorf("meeklike: decode ts: %w", err)
	}
	hi, lo, err := dec.DecodeU128()
	if err != nil {
		return fmt.Errorf("meeklike: decode stream_id: %w", err)
	}
	inner, err := dec.DecodeBytes()
	if err != nil {
		return fmt.Errorf("meeklike: decode inner: %w", err)
	}
	if dec.Remaining() != 0 {
		return fmt.Errorf("meeklike: trailing bytes in Datagram (%d)", dec.Remaining())
	}
	d.Ts = ts
	d.StreamID = StreamID{Hi: hi, Lo: lo}
	d.Inner = inner
	return nil
}

// PresharedSecret holds the two ChaCha8Poly1305 AEADs (upstream and
// downstream) derived from a shared key string. It mirrors the Rust
// crypto::PresharedSecret.
type PresharedSecret struct {
	up *chacha20poly1305.AEAD
	dn *chacha20poly1305.AEAD
}

// NewPresharedSecret derives the upstream/downstream AEAD keys from the
// 32-byte key material (which is blake3::hash(key_string) at the call site).
// The keys are blake3::keyed_hash(psk_context, material).
func NewPresharedSecret(material [32]byte) *PresharedSecret {
	upKey := blake3.KeyedHash(pskContextUp, material[:])
	dnKey := blake3.KeyedHash(pskContextDn, material[:])
	up, err := chacha20poly1305.New(upKey[:])
	if err != nil {
		panic(fmt.Sprintf("meeklike: chacha8 up key: %v", err))
	}
	dn, err := chacha20poly1305.New(dnKey[:])
	if err != nil {
		panic(fmt.Sprintf("meeklike: chacha8 dn key: %v", err))
	}
	return &PresharedSecret{up: up, dn: dn}
}

// EncryptUp encrypts data with the upstream (client->server) AEAD. A 12-byte
// random nonce is prepended to the ciphertext: output = nonce || ciphertext.
func (p *PresharedSecret) EncryptUp(data []byte) []byte {
	return p.encrypt(p.up, data)
}

// DecryptUp decrypts a nonce-prepended upstream ciphertext.
func (p *PresharedSecret) DecryptUp(data []byte) ([]byte, error) {
	return p.decrypt(p.up, data)
}

// EncryptDn encrypts data with the downstream (server->client) AEAD.
func (p *PresharedSecret) EncryptDn(data []byte) []byte {
	return p.encrypt(p.dn, data)
}

// DecryptDn decrypts a nonce-prepended downstream ciphertext.
func (p *PresharedSecret) DecryptDn(data []byte) ([]byte, error) {
	return p.decrypt(p.dn, data)
}

func (p *PresharedSecret) encrypt(a *chacha20poly1305.AEAD, data []byte) []byte {
	var nonce [12]byte
	_, _ = rand.Read(nonce[:])
	ct := a.Seal(nil, nonce[:], data, nil)
	out := make([]byte, 0, 12+len(ct))
	out = append(out, nonce[:]...)
	out = append(out, ct...)
	return out
}

func (p *PresharedSecret) decrypt(a *chacha20poly1305.AEAD, data []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, errors.New("meeklike: missing nonce")
	}
	nonce := data[:12]
	ct := data[12:]
	return a.Open(nil, nonce, ct, nil)
}
