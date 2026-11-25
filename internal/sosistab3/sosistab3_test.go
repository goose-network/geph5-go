package sosistab3

import (
	"bytes"
	"testing"
)

// TestEncryptDecryptRoundTrip locks in the record framing: Encrypt must emit
// enc_length(4)||tag_length(16)||enc_body(N)||tag_body(16), and Decrypt must
// recover the plaintext. The 4-byte case is the regression guard for the
// length-encryption bug where Seal was called with the length bytes as AAD and
// a nil plaintext, producing a 16-byte tag-only buffer that panicked on [:20].
func TestEncryptDecryptRoundTrip(t *testing.T) {
	ss := make([]byte, 32)
	for i := range ss {
		ss[i] = byte(i + 1)
	}
	for _, obfs := range []ObfsParams{{}, {ObfsLengths: true}} {
		client, err := NewState(ss, false, obfs)
		if err != nil {
			t.Fatalf("client NewState: %v", err)
		}
		server, err := NewState(ss, true, obfs)
		if err != nil {
			t.Fatalf("server NewState: %v", err)
		}
		// The first message is a 4-byte big-endian length prefix (exactly what
		// session.writePrependLength feeds through the pipe); then assorted
		// sizes including empty and multi-record streams.
		msgs := [][]byte{
			{0, 0, 0, 4},
			{},
			{0x41},
			bytes.Repeat([]byte{0x42}, 1999), // just under the obfs padding threshold
			bytes.Repeat([]byte{0x43}, 4096),
		}
		var wire []byte
		for _, m := range msgs {
			client.Encrypt(m, &wire)
		}
		var got []byte
		off := 0
		for off < len(wire) {
			n, err := server.Decrypt(wire[off:], &got)
			if err != nil {
				t.Fatalf("obfs=%+v decrypt at off %d: %v", obfs, off, err)
			}
			if n == 0 {
				t.Fatalf("obfs=%+v: zero consumed at off %d", obfs, off)
			}
			off += n
		}
		var want []byte
		for _, m := range msgs {
			want = append(want, m...)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("obfs=%+v round-trip mismatch: got %d bytes, want %d", obfs, len(got), len(want))
		}
	}
}

// TestEncryptLengthPrefixFraming checks the exact byte layout of a single
// 4-byte record: 4 + 16 + 4 + 16 = 40 bytes on the wire (no obfs padding).
func TestEncryptLengthPrefixFraming(t *testing.T) {
	ss := make([]byte, 32)
	client, err := NewState(ss, false, ObfsParams{})
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	var wire []byte
	client.Encrypt([]byte{0, 0, 0, 4}, &wire)
	if len(wire) != 40 {
		t.Fatalf("wire len = %d, want 40 (4+16+4+16)", len(wire))
	}
}