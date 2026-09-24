package stdcode

import (
	"bytes"
	"testing"
)

// Known bincode 1.3.3 (VarintEncoding, LittleEndian) encodings, verified
// against the reference Rust implementation. These pin our codec to the
// exact wire format geph5 uses.

func TestEncodeU64Varint(t *testing.T) {
	cases := []struct {
		v    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{250, []byte{0xfa}},
		{251, []byte{251, 0xfb, 0x00}},               // tagU16 + LE u16
		{0xFFFF, []byte{251, 0xff, 0xff}},            // max u16
		{0x10000, []byte{252, 0x00, 0x00, 0x01, 0x00}}, // tagU32 + LE u32
		{0xFFFFFFFF, []byte{252, 0xff, 0xff, 0xff, 0xff}},
		{0x100000000, []byte{253, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}},
	}
	for _, c := range cases {
		e := NewEncoder()
		e.EncodeU64(c.v)
		if !bytes.Equal(e.Bytes(), c.want) {
			t.Errorf("EncodeU64(%#x) = %v, want %v", c.v, e.Bytes(), c.want)
		}
		d := NewDecoder(e.Bytes())
		got, err := d.DecodeU64()
		if err != nil || got != c.v {
			t.Errorf("DecodeU64(%v) = %d, %v, want %d", c.want, got, err, c.v)
		}
	}
}

func TestEncodeI64Zigzag(t *testing.T) {
	// bincode zig-zag: 0 -> 0, -1 -> 1, 1 -> 2, -2 -> 3, 2 -> 4
	cases := []struct {
		v    int64
		want []byte
	}{
		{0, []byte{0x00}},
		{-1, []byte{0x01}},
		{1, []byte{0x02}},
		{-2, []byte{0x03}},
		{2, []byte{0x04}},
		{125, []byte{0xfa}},                  // 125 -> 250, fits in one byte
		{-126, []byte{251, 0xfb, 0x00}},      // -126 -> 251, needs tagU16 + LE(251)
	}
	for _, c := range cases {
		e := NewEncoder()
		e.EncodeI64(c.v)
		if !bytes.Equal(e.Bytes(), c.want) {
			t.Errorf("EncodeI64(%d) = %v, want %v", c.v, e.Bytes(), c.want)
		}
		d := NewDecoder(e.Bytes())
		got, err := d.DecodeI64()
		if err != nil || got != c.v {
			t.Errorf("DecodeI64(%v) = %d, %v, want %d", c.want, got, err, c.v)
		}
	}
}

func TestEncodeBytes(t *testing.T) {
	e := NewEncoder()
	e.EncodeBytes([]byte("hello"))
	// u32 length (5) as varint = 0x05, then "hello"
	want := append([]byte{0x05}, []byte("hello")...)
	if !bytes.Equal(e.Bytes(), want) {
		t.Fatalf("EncodeBytes = %v, want %v", e.Bytes(), want)
	}
	d := NewDecoder(e.Bytes())
	got, err := d.DecodeBytes()
	if err != nil || string(got) != "hello" {
		t.Fatalf("DecodeBytes = %q, %v", got, err)
	}
}

func TestEncodeString(t *testing.T) {
	e := NewEncoder()
	e.EncodeString("geph")
	d := NewDecoder(e.Bytes())
	got, err := d.DecodeString()
	if err != nil || got != "geph" {
		t.Fatalf("roundtrip string: got %q %v", got, err)
	}
}

func TestEncodeOption(t *testing.T) {
	// None
	e := NewEncoder()
	e.EncodeOption(false, nil)
	if !bytes.Equal(e.Bytes(), []byte{0x00}) {
		t.Fatalf("None = %v, want [0]", e.Bytes())
	}
	// Some(42u8)
	e = NewEncoder()
	e.EncodeOption(true, func() { e.EncodeU8(42) })
	if !bytes.Equal(e.Bytes(), []byte{0x01, 0x2a}) {
		t.Fatalf("Some(42) = %v, want [1,42]", e.Bytes())
	}
	d := NewDecoder(e.Bytes())
	has, err := d.DecodeOption()
	if err != nil || !has {
		t.Fatalf("DecodeOption Some: has=%v err=%v", has, err)
	}
	v, err := d.DecodeU8()
	if err != nil || v != 42 {
		t.Fatalf("inner u8 = %d %v", v, err)
	}
}

func TestDecodeEnum(t *testing.T) {
	e := NewEncoder()
	e.EncodeU32(2) // variant index 2
	d := NewDecoder(e.Bytes())
	idx, err := d.DecodeEnum()
	if err != nil || idx != 2 {
		t.Fatalf("enum idx = %d %v", idx, err)
	}
}

func TestTrailingDetection(t *testing.T) {
	e := NewEncoder()
	e.EncodeU8(1)
	e.EncodeU8(2) // extra
	d := NewDecoder(e.Bytes())
	_, _ = d.DecodeU8()
	if d.Remaining() != 1 {
		t.Fatalf("expected 1 trailing byte, got %d", d.Remaining())
	}
}
