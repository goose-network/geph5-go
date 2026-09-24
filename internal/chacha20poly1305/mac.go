// Self-contained Poly1305 implementation (RFC 8439), vendored from the
// public-domain golang.org/x/crypto/internal/poly1305 generic implementation
// (sum_generic.go, poly1305.go, mac_noasm.go). Vendored here because
// x/crypto/internal is not importable outside that module.
//
// The only change is the package name and removal of the assembly build-tag
// split (we always use the generic path).

package chacha20poly1305

import (
	"crypto/subtle"
	"encoding/binary"
	"math/bits"
)

// polyTagSize is the Poly1305 tag size in bytes.
const polyTagSize = 16

// poly1305MAC is a streaming Poly1305 MAC keyed with a 32-byte one-time key.
type poly1305MAC struct {
	macState
	buffer [polyTagSize]byte
	offset int
}

func newPoly1305(key *[32]byte) *poly1305MAC {
	m := &poly1305MAC{}
	initializeMAC(key, &m.macState)
	return m
}

// macState holds numbers in saturated 64-bit little-endian limbs. That is,
// the value of [x0, x1, x2] is x[0] + x[1] * 2⁶⁴ + x[2] * 2¹²⁸.
type macState struct {
	// h is the main accumulator, modulo 2¹³⁰ - 5 (but may grow larger during
	// and after rounds; remains below 2 * (2¹³⁰ - 5)).
	h [3]uint64
	// r and s are the private key components.
	r [2]uint64
	s [2]uint64
}

// Write splits the incoming message into 16-byte chunks and passes them to
// updateMAC. It buffers incomplete chunks.
func (h *poly1305MAC) Write(p []byte) (int, error) {
	nn := len(p)
	if h.offset > 0 {
		n := copy(h.buffer[h.offset:], p)
		if h.offset+n < polyTagSize {
			h.offset += n
			return nn, nil
		}
		p = p[n:]
		h.offset = 0
		updateMAC(&h.macState, h.buffer[:])
	}
	if n := len(p) - (len(p) % polyTagSize); n > 0 {
		updateMAC(&h.macState, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		h.offset += copy(h.buffer[h.offset:], p)
	}
	return nn, nil
}

// Sum flushes the last incomplete chunk from the buffer, if any, and generates
// the 16-byte MAC. It does not modify the streaming state.
func (h *poly1305MAC) Sum(out []byte) []byte {
	state := h.macState
	if h.offset > 0 {
		updateMAC(&state, h.buffer[:h.offset])
	}
	var tag [polyTagSize]byte
	finalizeMAC(&tag, &state.h, &state.s)
	return append(out, tag[:]...)
}

// Verify computes the MAC and returns whether it matches expected.
func (h *poly1305MAC) Verify(expected []byte) bool {
	state := h.macState
	if h.offset > 0 {
		updateMAC(&state, h.buffer[:h.offset])
	}
	var tag [polyTagSize]byte
	finalizeMAC(&tag, &state.h, &state.s)
	return subtle.ConstantTimeCompare(expected, tag[:]) == 1
}

// [rMask0, rMask1] is the Poly1305 clamping mask in little-endian.
const (
	rMask0 = 0x0FFFFFFC0FFFFFFF
	rMask1 = 0x0FFFFFFC0FFFFFFC
)

// initializeMAC loads the 256-bit key into the two 128-bit secret values r, s.
func initializeMAC(key *[32]byte, m *macState) {
	m.r[0] = binary.LittleEndian.Uint64(key[0:8]) & rMask0
	m.r[1] = binary.LittleEndian.Uint64(key[8:16]) & rMask1
	m.s[0] = binary.LittleEndian.Uint64(key[16:24])
	m.s[1] = binary.LittleEndian.Uint64(key[24:32])
}

// uint128 holds a 128-bit number as two 64-bit limbs.
type uint128 struct{ lo, hi uint64 }

func mul64(a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	return uint128{lo, hi}
}

func add128(a, b uint128) uint128 {
	lo, c := bits.Add64(a.lo, b.lo, 0)
	hi, c := bits.Add64(a.hi, b.hi, c)
	if c != 0 {
		panic("poly1305: unexpected overflow")
	}
	return uint128{lo, hi}
}

func shiftRightBy2(a uint128) uint128 {
	a.lo = a.lo>>2 | (a.hi&3)<<62
	a.hi = a.hi >> 2
	return a
}

// updateMAC absorbs msg into the state.h accumulator. For each 128-bit chunk m,
// it computes h₊ = (h + m) * r mod 2¹³⁰ - 5. If msg is not a multiple of
// TagSize, the last incomplete chunk is treated as the final one.
func updateMAC(state *macState, msg []byte) {
	h0, h1, h2 := state.h[0], state.h[1], state.h[2]
	r0, r1 := state.r[0], state.r[1]

	for len(msg) > 0 {
		var c uint64

		if len(msg) >= polyTagSize {
			h0, c = bits.Add64(h0, binary.LittleEndian.Uint64(msg[0:8]), 0)
			h1, c = bits.Add64(h1, binary.LittleEndian.Uint64(msg[8:16]), c)
			h2 += c + 1
			msg = msg[polyTagSize:]
		} else {
			var buf [polyTagSize]byte
			copy(buf[:], msg)
			buf[len(msg)] = 1
			h0, c = bits.Add64(h0, binary.LittleEndian.Uint64(buf[0:8]), 0)
			h1, c = bits.Add64(h1, binary.LittleEndian.Uint64(buf[8:16]), c)
			h2 += c
			msg = nil
		}

		h0r0 := mul64(h0, r0)
		h1r0 := mul64(h1, r0)
		h2r0 := mul64(h2, r0)
		h0r1 := mul64(h0, r1)
		h1r1 := mul64(h1, r1)
		h2r1 := mul64(h2, r1)

		if h2r0.hi != 0 {
			panic("poly1305: unexpected overflow")
		}
		if h2r1.hi != 0 {
			panic("poly1305: unexpected overflow")
		}

		m0 := h0r0
		m1 := add128(h1r0, h0r1)
		m2 := add128(h2r0, h1r1)
		m3 := h2r1

		t0 := m0.lo
		t1, c := bits.Add64(m1.lo, m0.hi, 0)
		t2, c := bits.Add64(m2.lo, m1.hi, c)
		t3, _ := bits.Add64(m3.lo, m2.hi, c)

		h0, h1, h2 = t0, t1, t2&maskLow2Bits
		cc := uint128{t2 & maskNotLow2Bits, t3}

		h0, c = bits.Add64(h0, cc.lo, 0)
		h1, c = bits.Add64(h1, cc.hi, c)
		h2 += c

		cc = shiftRightBy2(cc)

		h0, c = bits.Add64(h0, cc.lo, 0)
		h1, c = bits.Add64(h1, cc.hi, c)
		h2 += c
	}

	state.h[0], state.h[1], state.h[2] = h0, h1, h2
}

const (
	maskLow2Bits    uint64 = 0x0000000000000003
	maskNotLow2Bits uint64 = ^maskLow2Bits
)

// select64 returns x if v == 1 and y if v == 0, in constant time.
func select64(v, x, y uint64) uint64 { return ^(v-1)&x | (v-1)&y }

// [p0, p1, p2] is 2¹³⁰ - 5 in little endian order.
const (
	p0 = 0xFFFFFFFFFFFFFFFB
	p1 = 0xFFFFFFFFFFFFFFFF
	p2 = 0x0000000000000003
)

// finalizeMAC completes the modular reduction of h and computes
// out = h + s mod 2¹²⁸.
func finalizeMAC(out *[16]byte, h *[3]uint64, s *[2]uint64) {
	h0, h1, h2 := h[0], h[1], h[2]

	hMinusP0, b := bits.Sub64(h0, p0, 0)
	hMinusP1, b := bits.Sub64(h1, p1, b)
	_, b = bits.Sub64(h2, p2, b)

	h0 = select64(b, h0, hMinusP0)
	h1 = select64(b, h1, hMinusP1)

	h0, c := bits.Add64(h0, s[0], 0)
	h1, _ = bits.Add64(h1, s[1], c)

	binary.LittleEndian.PutUint64(out[0:8], h0)
	binary.LittleEndian.PutUint64(out[8:16], h1)
}
