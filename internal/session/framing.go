// framing.go provides the read_prepend_length / write_prepend_length helpers
// used by the exit handshake and the tunnel-open-response framing. Each message
// is a 4-byte big-endian u32 length prefix followed by that many bytes, with a
// 100KB cap (matching geph5_misc_rpc::read_prepend_length).
package session

import (
	"encoding/binary"
	"fmt"
	"io"
)

// maxPrependLength is the 100KB cap from read_prepend_length / write_prepend_length.
const maxPrependLength = 100 * 1024

// readPrependLength reads a 4-byte big-endian u32 length prefix followed by
// that many bytes, mirroring geph5_misc_rpc::read_prepend_length. Messages
// larger than maxPrependLength (100KB) are rejected.
func readPrependLength(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("session: reading length prefix: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxPrependLength {
		return nil, fmt.Errorf("session: message too large: %d > %d", n, maxPrependLength)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("session: reading message body: %w", err)
	}
	return buf, nil
}

// writePrependLength writes a 4-byte big-endian u32 length prefix followed by
// the payload, mirroring geph5_misc_rpc::write_prepend_length. Messages larger
// than maxPrependLength (100KB) are rejected.
func writePrependLength(w io.Writer, payload []byte) error {
	if len(payload) > maxPrependLength {
		return fmt.Errorf("session: payload too large: %d > %d", len(payload), maxPrependLength)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("session: writing length prefix: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("session: writing payload: %w", err)
	}
	return nil
}
