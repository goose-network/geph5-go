// Package hexdialer implements the sillad-hex hex-encoding obfuscation pipe.
//
// The entire byte stream is encoded as a continuous lowercase-hex string with
// NO framing and NO length prefix. On read, an odd trailing byte is buffered
// across reads (a single TCP read may deliver an odd number of hex chars).
// Wire-compatible with sillad_hex::HexPipe.
package hexdialer

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"time"

	"github.com/geph-official/geph5-go/internal/sillad"
)

// HexPipe hex-encodes all writes and hex-decodes all reads over an inner Pipe.
type HexPipe struct {
	inner      sillad.Pipe
	readLeftover []byte
	readMu     sync.Mutex
	writeMu    sync.Mutex
}

// New wraps an inner pipe.
func New(inner sillad.Pipe) *HexPipe { return &HexPipe{inner: inner} }

func (p *HexPipe) Protocol() string      { return "hex" }
func (p *HexPipe) RemoteAddrStr() string { return p.inner.RemoteAddrStr() }
func (p *HexPipe) SharedSecret() []byte  { return p.inner.SharedSecret() }

// Read decodes hex from the inner stream into b.
func (p *HexPipe) Read(b []byte) (int, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	// First, drain any already-decoded leftover bytes.
	if len(p.readLeftover) > 0 {
		n := copy(b, p.readLeftover)
		p.readLeftover = p.readLeftover[n:]
		return n, nil
	}
	raw := make([]byte, 8192)
	for {
		n, err := p.inner.Read(raw)
		if n > 0 {
			p.readLeftover = append(p.readLeftover, raw[:n]...)
			// Decode as many complete hex pairs as possible.
			decLen := len(p.readLeftover) / 2 * 2
			if decLen == 0 {
				if err != nil {
					return 0, err
				}
				continue
			}
			decoded, derr := hex.DecodeString(string(p.readLeftover[:decLen]))
			if derr != nil {
				return 0, io.ErrUnexpectedEOF
			}
			p.readLeftover = append([]byte(nil), p.readLeftover[decLen:]...)
			out := copy(b, decoded)
			if out < len(decoded) {
				p.readLeftover = append(decoded[out:], p.readLeftover...)
			}
			return out, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

// Write encodes b as lowercase hex and writes to the inner stream.
func (p *HexPipe) Write(b []byte) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	encoded := hex.EncodeToString(b)
	// Write all encoded bytes; net.Conn.Write may do partial writes.
	written := 0
	enc := []byte(encoded)
	for written < len(enc) {
		n, err := p.inner.Write(enc[written:])
		written += n
		if err != nil {
			return len(b), err
		}
	}
	return len(b), nil
}

func (p *HexPipe) Close() error                    { return p.inner.Close() }
func (p *HexPipe) LocalAddr() net.Addr             { return p.inner.LocalAddr() }
func (p *HexPipe) RemoteAddr() net.Addr            { return p.inner.RemoteAddr() }
func (p *HexPipe) SetDeadline(t time.Time) error   { return p.inner.SetDeadline(t) }
func (p *HexPipe) SetReadDeadline(t time.Time) error  { return p.inner.SetReadDeadline(t) }
func (p *HexPipe) SetWriteDeadline(t time.Time) error { return p.inner.SetWriteDeadline(t) }

// Dialer wraps an inner Dialer with hex encoding.
type Dialer struct{ Inner sillad.Dialer }

func (d Dialer) Dial(ctx context.Context) (sillad.Pipe, error) {
	inner, err := d.Inner.Dial(ctx)
	if err != nil {
		return nil, err
	}
	return New(inner), nil
}
