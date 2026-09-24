// Package chacha20poly1305 implements the ChaCha8Poly1305 AEAD used by the
// geph5 meeklike transport.
//
// geph5's meeklike uses the *chacha20poly1305* Rust crate's ChaCha8Poly1305
// variant: the same Poly1305 + ChaCha construction as RFC 8439, but with only
// 8 rounds of ChaCha (4 column+diagonal round pairs) instead of 20. The
// standard golang.org/x/crypto/chacha20poly1305 package only provides the
// 20-round variant, so this package implements the 8-round variant directly,
// with a self-contained Poly1305 (so it does not depend on x/crypto/internal).
//
// The construction (matching the chacha20poly1305 crate's ChaCha8Poly1305):
//   - polyKey = ChaCha8(key, nonce, counter=0)[0:32]
//   - ciphertext = plaintext XOR ChaCha8(key, nonce, counter=1..)
//   - tag = Poly1305(polyKey) over: AAD || pad16 || ciphertext || pad16 ||
//           len(AAD) as u64 LE || len(ciphertext) as u64 LE
//   - output = ciphertext || tag
//
// Nonce size is 12 bytes; key size is 32 bytes; tag size is 16 bytes. No AAD
// is used by meeklike, but the implementation supports it for correctness.
package chacha20poly1305

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	// KeySize is the ChaCha8Poly1305 key size in bytes.
	KeySize = 32
	// NonceSize is the standard ChaCha nonce size in bytes.
	NonceSize = 12
	// TagSize is the Poly1305 tag size in bytes.
	TagSize = 16
)

// chacha8State is the 16-word ChaCha state.
type chacha8State [16]uint32

// constants "expand 32-byte k"
const (
	j0 uint32 = 0x61707865
	j1 uint32 = 0x3320646e
	j2 uint32 = 0x79622d32
	j3 uint32 = 0x6b206574
)

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)
	return a, b, c, d
}

// chacha8Block computes the 64-byte keystream block for the given key, nonce,
// and 32-bit counter, using 8 rounds (4 column+diagonal pairs). This matches
// the chacha20poly1305 crate's ChaCha8Poly1305 round count.
func chacha8Block(key [32]byte, nonce [12]byte, counter uint32) [64]byte {
	var s chacha8State
	s[0], s[1], s[2], s[3] = j0, j1, j2, j3
	s[4] = binary.LittleEndian.Uint32(key[0:4])
	s[5] = binary.LittleEndian.Uint32(key[4:8])
	s[6] = binary.LittleEndian.Uint32(key[8:12])
	s[7] = binary.LittleEndian.Uint32(key[12:16])
	s[8] = binary.LittleEndian.Uint32(key[16:20])
	s[9] = binary.LittleEndian.Uint32(key[20:24])
	s[10] = binary.LittleEndian.Uint32(key[24:28])
	s[11] = binary.LittleEndian.Uint32(key[28:32])
	s[12] = counter
	s[13] = binary.LittleEndian.Uint32(nonce[0:4])
	s[14] = binary.LittleEndian.Uint32(nonce[4:8])
	s[15] = binary.LittleEndian.Uint32(nonce[8:12])

	x := s

	// 8 rounds = 4 iterations of (column round + diagonal round).
	for i := 0; i < 4; i++ {
		// Column round.
		x[0], x[4], x[8], x[12] = quarterRound(x[0], x[4], x[8], x[12])
		x[1], x[5], x[9], x[13] = quarterRound(x[1], x[5], x[9], x[13])
		x[2], x[6], x[10], x[14] = quarterRound(x[2], x[6], x[10], x[14])
		x[3], x[7], x[11], x[15] = quarterRound(x[3], x[7], x[11], x[15])
		// Diagonal round.
		x[0], x[5], x[10], x[15] = quarterRound(x[0], x[5], x[10], x[15])
		x[1], x[6], x[11], x[12] = quarterRound(x[1], x[6], x[11], x[12])
		x[2], x[7], x[8], x[13] = quarterRound(x[2], x[7], x[8], x[13])
		x[3], x[4], x[9], x[14] = quarterRound(x[3], x[4], x[9], x[14])
	}

	for i := 0; i < 16; i++ {
		x[i] += s[i]
	}

	var out [64]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:i*4+4], x[i])
	}
	return out
}

// xorKeystream XORs dst with the ChaCha8 keystream starting at the given
// counter. dst and src must be the same length.
func xorKeystream(dst, src []byte, key [32]byte, nonce [12]byte, counter uint32) {
	ctr := counter
	off := 0
	for off < len(src) {
		block := chacha8Block(key, nonce, ctr)
		n := len(src) - off
		if n > 64 {
			n = 64
		}
		for i := 0; i < n; i++ {
			dst[off+i] = src[off+i] ^ block[i]
		}
		off += n
		ctr++
	}
}

// AEAD is a ChaCha8Poly1305 AEAD keyed with a 32-byte key.
type AEAD struct {
	key [32]byte
}

// New returns a ChaCha8Poly1305 AEAD with the given 32-byte key.
func New(key []byte) (*AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha20poly1305: bad key size")
	}
	var k [32]byte
	copy(k[:], key)
	return &AEAD{key: k}, nil
}

func (c *AEAD) NonceSize() int { return NonceSize }
func (c *AEAD) Overhead() int  { return TagSize }

func (c *AEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("chacha20poly1305: bad nonce size")
	}
	var n [12]byte
	copy(n[:], nonce)
	ret, out := sliceForAppend(dst, len(plaintext)+TagSize)
	ciphertext, tag := out[:len(plaintext)], out[len(plaintext):]

	// polyKey = block 0 keystream.
	var polyKey [32]byte
	block0 := chacha8Block(c.key, n, 0)
	copy(polyKey[:], block0[:32])

	// Encrypt plaintext starting at counter 1.
	xorKeystream(ciphertext, plaintext, c.key, n, 1)

	// Poly1305 over AAD || pad || ciphertext || pad || len(AAD) || len(ct).
	mac := newPoly1305(&polyKey)
	writeWithPadding(mac, additionalData)
	writeWithPadding(mac, ciphertext)
	writeUint64(mac, len(additionalData))
	writeUint64(mac, len(plaintext))
	mac.Sum(tag[:0])

	return ret
}

func (c *AEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("chacha20poly1305: bad nonce size")
	}
	if len(ciphertext) < TagSize {
		return nil, errors.New("chacha20poly1305: ciphertext too short")
	}
	var n [12]byte
	copy(n[:], nonce)
	tag := ciphertext[len(ciphertext)-TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-TagSize]

	var polyKey [32]byte
	block0 := chacha8Block(c.key, n, 0)
	copy(polyKey[:], block0[:32])

	mac := newPoly1305(&polyKey)
	writeWithPadding(mac, additionalData)
	writeWithPadding(mac, ciphertext)
	writeUint64(mac, len(additionalData))
	writeUint64(mac, len(ciphertext))
	if !mac.Verify(tag) {
		return nil, errOpen
	}

	ret, out := sliceForAppend(dst, len(ciphertext))
	xorKeystream(out, ciphertext, c.key, n, 1)
	return ret, nil
}

var errOpen = errors.New("chacha20poly1305: message authentication failed")

func writeWithPadding(p *poly1305MAC, b []byte) {
	p.Write(b)
	if rem := len(b) % 16; rem != 0 {
		var buf [16]byte
		padLen := 16 - rem
		p.Write(buf[:padLen])
	}
}

func writeUint64(p *poly1305MAC, n int) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(n))
	p.Write(buf[:])
}

// sliceForAppend copies the Go standard library helper used by x/crypto.
func sliceForAppend(dst []byte, n int) (head, tail []byte) {
	if dst == nil {
		dst = []byte{}
	}
	if total := len(dst) + n; cap(dst) >= total {
		head = dst[:total]
	} else {
		head = make([]byte, total)
		copy(head, dst)
	}
	tail = head[len(dst):]
	return
}
