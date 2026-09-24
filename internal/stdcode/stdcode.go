// Package stdcode implements a Go codec compatible with the Rust `stdcode`
// crate (v0.1.14), which is a thin wrapper over bincode 1.3.3 configured with:
//
//   - Little-endian byte order
//   - VarintEncoding for all integer types (small integers use fewer bytes)
//   - 32-bit length prefixes for sequences, strings, and byte slices
//   - 1-byte tag for Option<T> (0 = None, 1 = Some)
//   - Enum variants tagged with a varint index (externally tagged)
//
// This package provides low-level encode/decode primitives. Higher-level
// types in other packages use these to implement BinaryMarshaler-style
// serialization matching the Rust serde + stdcode pipeline.
//
// The varint encoding here is bincode's, NOT protobuf's. bincode encodes a
// u64 as: if the value fits in a single byte with the high bit clear
// (0..=250), one byte; otherwise a tag byte (251..255) indicating the
// underlying width (u16/u32/u64/u128), followed by that many little-endian
// bytes. Signed integers are zig-zag encoded first.
package stdcode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
)

// Bincode varint tag bytes. When an integer does not fit in a single byte
// (0..=250), bincode emits one of these tags followed by the fixed-width
// little-endian value.
const (
	tagU16 = 251
	tagU32 = 252
	tagU64 = 253
	tagU128 = 254
	tagReserved = 255 // bincode reserves this; we treat as error on decode
)

// Encoder is a byte buffer that accumulates stdcode-encoded values.
type Encoder struct {
	buf []byte
}

// NewEncoder returns a fresh Encoder.
func NewEncoder() *Encoder { return &Encoder{} }

// Bytes returns the accumulated encoding.
func (e *Encoder) Bytes() []byte { return e.buf }

// EncodeU8 appends a single byte. u8 is NOT varint-encoded in bincode.
func (e *Encoder) EncodeU8(v uint8) { e.buf = append(e.buf, v) }

// EncodeBool appends a bool as a single byte (0 or 1).
func (e *Encoder) EncodeBool(v bool) {
	if v {
		e.buf = append(e.buf, 1)
	} else {
		e.buf = append(e.buf, 0)
	}
}

// EncodeU16 encodes a u16. bincode varint: if v <= 250, one byte; else
// tagU16 + 2 LE bytes.
func (e *Encoder) EncodeU16(v uint16) {
	encodeU64(e, uint64(v), 0xFFFF)
}

// EncodeU32 encodes a u32 with bincode varint encoding.
func (e *Encoder) EncodeU32(v uint32) {
	encodeU64(e, uint64(v), 0xFFFFFFFF)
}

// EncodeU64 encodes a u64 with bincode varint encoding.
func (e *Encoder) EncodeU64(v uint64) {
	encodeU64(e, v, math.MaxUint64)
}

// EncodeU128 encodes a u128 with bincode varint encoding. bincode encodes a
// u128 that does not fit in a single byte (0..=250) as tag 254 followed by
// 16 little-endian bytes.
func (e *Encoder) EncodeU128(hi, lo uint64) {
	if lo <= 250 && hi == 0 {
		e.buf = append(e.buf, byte(lo))
		return
	}
	var b [16]byte
	binary.LittleEndian.PutUint64(b[:8], lo)
	binary.LittleEndian.PutUint64(b[8:], hi)
	e.buf = append(e.buf, tagU128)
	e.buf = append(e.buf, b[:]...)
}

// EncodeU128Big encodes a *big.Int as a u128. Panics if the value is negative
// or exceeds 128 bits.
func (e *Encoder) EncodeU128Big(v *big.Int) {
	if v.Sign() < 0 {
		panic("stdcode: negative u128")
	}
	if v.BitLen() > 128 {
		panic("stdcode: u128 overflow")
	}
	var lo, hi uint64
	lo = v.Uint64()
	if v.BitLen() > 64 {
		hi = new(big.Int).Rsh(v, 64).Uint64()
	}
	e.EncodeU128(hi, lo)
}

// EncodeI8 encodes a signed 8-bit integer. bincode zig-zags then varints.
func (e *Encoder) EncodeI8(v int8) { e.EncodeU64(uint64(zigzag(int64(v), 0xFF))) }

// EncodeI16 encodes a signed 16-bit integer.
func (e *Encoder) EncodeI16(v int16) { e.EncodeU64(uint64(zigzag(int64(v), 0xFFFF))) }

// EncodeI32 encodes a signed 32-bit integer.
func (e *Encoder) EncodeI32(v int32) { e.EncodeU64(uint64(zigzag(int64(v), 0xFFFFFFFF))) }

// EncodeI64 encodes a signed 64-bit integer.
func (e *Encoder) EncodeI64(v int64) { e.EncodeU64(uint64(zigzag(v, -1))) }

// EncodeBytes encodes a byte slice: u32 length prefix (varint) then the bytes.
func (e *Encoder) EncodeBytes(b []byte) {
	e.EncodeU32(uint32(len(b)))
	e.buf = append(e.buf, b...)
}

// EncodeString encodes a Rust String (UTF-8) as length-prefixed bytes.
func (e *Encoder) EncodeString(s string) { e.EncodeBytes([]byte(s)) }

// EncodeSeqLen encodes the length of a sequence (Vec/array). Same as u32.
func (e *Encoder) EncodeSeqLen(n int) { e.EncodeU32(uint32(n)) }

// EncodeOption encodes an Option<T>: 0 for None, 1 for Some followed by the
// encoded value. The some function is only called when present is true.
func (e *Encoder) EncodeOption(present bool, some func()) {
	if present {
		e.buf = append(e.buf, 1)
		some()
	} else {
		e.buf = append(e.buf, 0)
	}
}

// EncodeRaw appends pre-encoded bytes verbatim. Useful for nested structs
// that have already been encoded.
func (e *Encoder) EncodeRaw(b []byte) { e.buf = append(e.buf, b...) }

// encodeU64 implements bincode's varint encoding for unsigned integers.
// bincode picks the smallest representation that holds the value: a single
// byte for 0..=250, otherwise the narrowest of u16/u32/u64 (selected by the
// value's magnitude, NOT the declared type width) prefixed with a tag byte.
// maxVal is only a sanity cap on the input width.
func encodeU64(e *Encoder, v, maxVal uint64) {
	if v <= 250 {
		e.buf = append(e.buf, byte(v))
		return
	}
	var b [8]byte
	switch {
	case v <= 0xFFFF:
		e.buf = append(e.buf, tagU16)
		binary.LittleEndian.PutUint16(b[:2], uint16(v))
		e.buf = append(e.buf, b[:2]...)
	case v <= 0xFFFFFFFF:
		e.buf = append(e.buf, tagU32)
		binary.LittleEndian.PutUint32(b[:4], uint32(v))
		e.buf = append(e.buf, b[:4]...)
	default:
		e.buf = append(e.buf, tagU64)
		binary.LittleEndian.PutUint64(b[:8], v)
		e.buf = append(e.buf, b[:8]...)
	}
	_ = maxVal
}

// zigzag maps a signed integer to an unsigned one for varint encoding.
// mask is the bit-mask for the integer's width (e.g. 0xFF for i8), used to
// keep the result within width after the transform.
func zigzag(v, mask int64) uint64 {
	return uint64((v << 1) ^ (v >> 63)) & uint64(mask)
}

// Decoder reads stdcode-encoded values from a byte slice.
type Decoder struct {
	buf []byte
	pos int
}

// NewDecoder returns a Decoder over b.
func NewDecoder(b []byte) *Decoder { return &Decoder{buf: b} }

// Remaining returns the number of unread bytes.
func (d *Decoder) Remaining() int { return len(d.buf) - d.pos }

// EOF reports whether the decoder is at end of input.
func (d *Decoder) EOF() bool { return d.pos >= len(d.buf) }

// Position returns the current read offset.
func (d *Decoder) Position() int { return d.pos }

// RemainingBytes returns the unread portion (without advancing).
func (d *Decoder) RemainingBytes() []byte { return d.buf[d.pos:] }

// Skip advances the read position by n bytes.
func (d *Decoder) Skip(n int) error {
	if err := d.need(n); err != nil {
		return err
	}
	d.pos += n
	return nil
}

// NeedExact errors if fewer than n bytes remain, and is a no-op otherwise.
// Used by fixed-size array decoders that want to assert exact tail length.
func (d *Decoder) NeedExact(n int) error {
	if d.Remaining() != n {
		return fmt.Errorf("stdcode: expected exactly %d bytes, have %d", n, d.Remaining())
	}
	return nil
}

func (d *Decoder) need(n int) error {
	if d.pos+n > len(d.buf) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// DecodeU8 reads a single byte.
func (d *Decoder) DecodeU8() (uint8, error) {
	if err := d.need(1); err != nil {
		return 0, err
	}
	v := d.buf[d.pos]
	d.pos++
	return v, nil
}

// DecodeBool reads a bool.
func (d *Decoder) DecodeBool() (bool, error) {
	v, err := d.DecodeU8()
	if err != nil {
		return false, err
	}
	return v != 0, nil
}

// DecodeU16 reads a varint-encoded u16.
func (d *Decoder) DecodeU16() (uint16, error) {
	v, err := d.decodeU64()
	return uint16(v), err
}

// DecodeU32 reads a varint-encoded u32.
func (d *Decoder) DecodeU32() (uint32, error) {
	v, err := d.decodeU64()
	return uint32(v), err
}

// DecodeU64 reads a varint-encoded u64.
func (d *Decoder) DecodeU64() (uint64, error) { return d.decodeU64() }

// DecodeU128 reads a varint-encoded u128, returning the high and low 64-bit
// halves. Unlike DecodeU64, this supports the full 128-bit range.
func (d *Decoder) DecodeU128() (hi, lo uint64, err error) {
	if err = d.need(1); err != nil {
		return 0, 0, err
	}
	first := d.buf[d.pos]
	d.pos++
	if first <= 250 {
		return 0, uint64(first), nil
	}
	switch first {
	case tagU16:
		if err = d.need(2); err != nil {
			return 0, 0, err
		}
		v := binary.LittleEndian.Uint16(d.buf[d.pos : d.pos+2])
		d.pos += 2
		return 0, uint64(v), nil
	case tagU32:
		if err = d.need(4); err != nil {
			return 0, 0, err
		}
		v := binary.LittleEndian.Uint32(d.buf[d.pos : d.pos+4])
		d.pos += 4
		return 0, uint64(v), nil
	case tagU64:
		if err = d.need(8); err != nil {
			return 0, 0, err
		}
		v := binary.LittleEndian.Uint64(d.buf[d.pos : d.pos+8])
		d.pos += 8
		return 0, v, nil
	case tagU128:
		if err = d.need(16); err != nil {
			return 0, 0, err
		}
		lo = binary.LittleEndian.Uint64(d.buf[d.pos : d.pos+8])
		hi = binary.LittleEndian.Uint64(d.buf[d.pos+8 : d.pos+16])
		d.pos += 16
		return hi, lo, nil
	default:
		return 0, 0, fmt.Errorf("stdcode: invalid varint tag %d", first)
	}
}

// DecodeU128Big reads a varint-encoded u128 into a *big.Int.
func (d *Decoder) DecodeU128Big() (*big.Int, error) {
	hi, lo, err := d.DecodeU128()
	if err != nil {
		return nil, err
	}
	v := new(big.Int).SetUint64(lo)
	if hi != 0 {
		v.Or(v, new(big.Int).Lsh(new(big.Int).SetUint64(hi), 64))
	}
	return v, nil
}

// DecodeI8 reads a signed 8-bit integer.
func (d *Decoder) DecodeI8() (int8, error) {
	v, err := d.decodeU64()
	if err != nil {
		return 0, err
	}
	return int8(unzigzag(v, 0xFF)), nil
}

// DecodeI16 reads a signed 16-bit integer.
func (d *Decoder) DecodeI16() (int16, error) {
	v, err := d.decodeU64()
	if err != nil {
		return 0, err
	}
	return int16(unzigzag(v, 0xFFFF)), nil
}

// DecodeI32 reads a signed 32-bit integer.
func (d *Decoder) DecodeI32() (int32, error) {
	v, err := d.decodeU64()
	if err != nil {
		return 0, err
	}
	return int32(unzigzag(v, 0xFFFFFFFF)), nil
}

// DecodeI64 reads a signed 64-bit integer.
func (d *Decoder) DecodeI64() (int64, error) {
	v, err := d.decodeU64()
	if err != nil {
		return 0, err
	}
	return int64(unzigzag(v, math.MaxUint64)), nil
}

// decodeU64 implements bincode's varint decoding.
func (d *Decoder) decodeU64() (uint64, error) {
	if err := d.need(1); err != nil {
		return 0, err
	}
	first := d.buf[d.pos]
	d.pos++
	if first <= 250 {
		return uint64(first), nil
	}
	switch first {
	case tagU16:
		if err := d.need(2); err != nil {
			return 0, err
		}
		v := binary.LittleEndian.Uint16(d.buf[d.pos : d.pos+2])
		d.pos += 2
		return uint64(v), nil
	case tagU32:
		if err := d.need(4); err != nil {
			return 0, err
		}
		v := binary.LittleEndian.Uint32(d.buf[d.pos : d.pos+4])
		d.pos += 4
		return uint64(v), nil
	case tagU64:
		if err := d.need(8); err != nil {
			return 0, err
		}
		v := binary.LittleEndian.Uint64(d.buf[d.pos : d.pos+8])
		d.pos += 8
		return v, nil
	case tagU128:
		// u128: 16 LE bytes. We only support the low 64 bits; values
		// exceeding u64 are not used anywhere in the geph5 protocol.
		if err := d.need(16); err != nil {
			return 0, err
		}
		v := binary.LittleEndian.Uint64(d.buf[d.pos : d.pos+8])
		d.pos += 16
		hi := binary.LittleEndian.Uint64(d.buf[d.pos-8 : d.pos])
		if hi != 0 {
			return 0, fmt.Errorf("stdcode: u128 value exceeds u64 range")
		}
		return v, nil
	default:
		return 0, fmt.Errorf("stdcode: invalid varint tag %d", first)
	}
}

// unzigzag reverses the zig-zag encoding. mask is the width's bit-mask.
func unzigzag(v, mask uint64) uint64 {
	v &= mask
	return (v >> 1) ^ (^(v&1) + 1)
}

// DecodeBytes reads a length-prefixed byte slice.
func (d *Decoder) DecodeBytes() ([]byte, error) {
	n, err := d.DecodeU32()
	if err != nil {
		return nil, err
	}
	if err := d.need(int(n)); err != nil {
		return nil, err
	}
	b := make([]byte, n)
	copy(b, d.buf[d.pos:d.pos+int(n)])
	d.pos += int(n)
	return b, nil
}

// DecodeFixedBytes reads exactly n raw bytes with no length prefix. This
// matches bincode's encoding of a fixed-size array [u8; N] (or [T; N] where
// T serializes to a fixed width), which is emitted as N contiguous bytes
// with no prefix.
func (d *Decoder) DecodeFixedBytes(n int) ([]byte, error) {
	if err := d.need(n); err != nil {
		return nil, err
	}
	b := make([]byte, n)
	copy(b, d.buf[d.pos:d.pos+n])
	d.pos += n
	return b, nil
}

// DecodeString reads a length-prefixed UTF-8 string.
func (d *Decoder) DecodeString() (string, error) {
	b, err := d.DecodeBytes()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodeSeqLen reads a sequence length (u32).
func (d *Decoder) DecodeSeqLen() (int, error) {
	n, err := d.DecodeU32()
	return int(n), err
}

// DecodeOption reads an Option tag. Returns (hasValue, nil). When hasValue
// is true, the caller must decode the inner value.
func (d *Decoder) DecodeOption() (bool, error) {
	v, err := d.DecodeU8()
	if err != nil {
		return false, err
	}
	switch v {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("stdcode: invalid option tag %d", v)
	}
}

// DecodeEnum reads an enum variant index (u32 varint). The caller uses the
// returned index to dispatch to the correct variant decoder.
func (d *Decoder) DecodeEnum() (uint32, error) { return d.DecodeU32() }

// ErrTrailing is returned by strict decoders when trailing bytes remain.
var ErrTrailing = errors.New("stdcode: trailing bytes")

// Serialize returns the stdcode encoding of v using v's MarshalStdcode.
func Serialize(v interface{ MarshalStdcode() ([]byte, error) }) ([]byte, error) {
	return v.MarshalStdcode()
}

// Deserialize decodes b into v using v's UnmarshalStdcode.
func Deserialize(b []byte, v interface{ UnmarshalStdcode([]byte) error }) error {
	return v.UnmarshalStdcode(b)
}
