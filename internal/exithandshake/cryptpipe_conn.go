// cryptpipe_conn.go extends exithandshake with a sillad.Pipe-compatible
// wrapper around the ChaCha20Poly1305 record framing, mirroring the Rust
// ClientExitCryptPipe.
//
// The Rust ClientExitCryptPipe splits the underlying pipe into a read half and
// a write half, then runs two background tasks: one decrypts incoming records
// (read_prepend_length + ChaCha20Poly1305) and feeds the plaintext into a
// duplex's "read" end; the other reads plaintext from a second duplex's "write"
// end, encrypts it into records, and write_prepend_length's them onto the
// pipe's write half. The Pipe interface then reads/writes against the two
// duplex halves, giving a plain net.Conn-style byte stream over the encrypted
// record framing.
//
// This file implements the same shape in Go using io.Pipe pairs and goroutines,
// exposed as ClientCryptPipe (a sillad.Pipe: net.Conn + Protocol/RemoteAddrStr/
// SharedSecret). Protocol() is "plain" and RemoteAddrStr() carries the
// underlying pipe's remote address, matching the Rust impl.
package exithandshake

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/geph-official/geph5-go/internal/sillad"
)

// maxCryptRecord is the 100KB cap from read_prepend_length / write_prepend_length.
const maxCryptRecord = 100 * 1024

// ClientCryptPipe is a sillad.Pipe that transparently applies the
// ChaCha20Poly1305 record framing over a duplex pair of io.Pipes, mirroring
// Rust's ClientExitCryptPipe.
type ClientCryptPipe struct {
	// connRead is the plaintext read side (decrypted inbound bytes). The
	// application reads from here.
	connRead *io.PipeReader
	// connWrite is the plaintext write side (bytes to be encrypted outbound).
	// The application writes to here.
	connWrite *io.PipeWriter

	// writeIn feeds the write loop; writeOut is read by the write loop.
	writeIn  *io.PipeWriter
	writeOut *io.PipeReader

	// underlying remote address string + protocol label.
	remoteStr string
	protocol  string

	// sharedSecret is carried through from the underlying pipe for interface
	// completeness (the X25519 path consumes the transport secret during the
	// handshake; the resulting pipe has none, but we preserve whatever the
	// inner pipe reported).
	sharedSecret []byte

	closeOnce sync.Once
	closed    chan struct{}

	// rawConn is the underlying net.Conn (for LocalAddr/RemoteAddr/deadlines).
	rawConn net.Conn

	// writeMu serializes outbound record writes (len prefix + ciphertext) so
	// they are not interleaved with other writers on rawConn.
	writeMu sync.Mutex
}

// NewClientCryptPipe wraps an authenticated sillad.Pipe in the
// ChaCha20Poly1305 record framing, returning a new sillad.Pipe. It mirrors
// Rust's ClientExitCryptPipe::new(pipe, read_key, write_key).
//
// The underlying pipe must be a net.Conn (every sillad.Pipe is). readKey is the
// exit->client (decrypt inbound) key; writeKey is the client->exit (encrypt
// outbound) key.
func NewClientCryptPipe(pipe sillad.Pipe, readKey, writeKey [32]byte) (*ClientCryptPipe, error) {
	rawConn, ok := pipe.(net.Conn)
	if !ok {
		// sillad.Pipe embeds net.Conn, so this should never happen.
		pipe.Close()
		return nil, errors.New("exithandshake: underlying pipe is not a net.Conn")
	}

	// Plaintext duplex for the application: writes to connWrite appear on
	// connRead (the read side the application reads from).
	connRead, connWrite := io.Pipe()
	// Plaintext duplex for outbound: the application writes to writeIn, the
	// write loop reads from writeOut.
	writeOut, writeIn := io.Pipe()

	cp := &ClientCryptPipe{
		connRead:     connRead,
		connWrite:    connWrite,
		writeIn:      writeIn,
		writeOut:     writeOut,
		remoteStr:    pipe.RemoteAddrStr(),
		protocol:     "plain",
		closed:       make(chan struct{}),
		rawConn:      rawConn,
		sharedSecret: pipe.SharedSecret(),
	}

	// Read loop: decrypt inbound records and feed plaintext into connWrite.
	go cp.readLoop(readKey)
	// Write loop: read plaintext from writeOut and encrypt outbound.
	go cp.writeLoop(writeKey)

	return cp, nil
}

// newChaCha20Poly1305 builds the AEAD from a 32-byte key.
func newChaCha20Poly1305(key [32]byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key[:])
}

// readLoop decrypts inbound records (4-byte BE length + ciphertext) and writes
// the plaintext into the plaintext duplex's write end (connWrite). On any error
// it closes connWrite with the error, signaling EOF/error to readers.
func (cp *ClientCryptPipe) readLoop(readKey [32]byte) {
	aead, err := newChaCha20Poly1305(readKey)
	if err != nil {
		cp.connWrite.CloseWithError(err)
		return
	}
	var counter uint64
	for {
		select {
		case <-cp.closed:
			cp.connWrite.CloseWithError(io.EOF)
			return
		default:
		}
		var lenBuf [4]byte
		if _, err := io.ReadFull(cp.rawConn, lenBuf[:]); err != nil {
			cp.connWrite.CloseWithError(io.EOF)
			return
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > maxCryptRecord {
			cp.connWrite.CloseWithError(errors.New("exithandshake: inbound record too large"))
			return
		}
		ciphertext := make([]byte, n)
		if _, err := io.ReadFull(cp.rawConn, ciphertext); err != nil {
			cp.connWrite.CloseWithError(io.EOF)
			return
		}
		nonce := nonceFor(counter)
		counter++
		plaintext, err := aead.Open(nil, nonce[:], ciphertext, nil)
		if err != nil {
			cp.connWrite.CloseWithError(errors.New("exithandshake: cannot decrypt"))
			return
		}
		if _, err := cp.connWrite.Write(plaintext); err != nil {
			// Reader closed; stop reading.
			return
		}
	}
}

// writeLoop reads plaintext from writeOut and encrypts it into outbound
// records written to rawConn.
func (cp *ClientCryptPipe) writeLoop(writeKey [32]byte) {
	aead, err := newChaCha20Poly1305(writeKey)
	if err != nil {
		return
	}
	var counter uint64
	buf := make([]byte, 8192)
	for {
		n, rerr := cp.writeOut.Read(buf)
		if n > 0 {
			nonce := nonceFor(counter)
			counter++
			ciphertext := aead.Seal(nil, nonce[:], buf[:n], nil)
			var lenBuf [4]byte
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ciphertext)))
			cp.writeMu.Lock()
			_, werr := cp.rawConn.Write(lenBuf[:])
			if werr == nil {
				_, werr = cp.rawConn.Write(ciphertext)
			}
			cp.writeMu.Unlock()
			if werr != nil {
				cp.shutdown(werr)
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}

// shutdown marks the pipe closed and unblocks readers/writers.
func (cp *ClientCryptPipe) shutdown(err error) {
	cp.closeOnce.Do(func() {
		close(cp.closed)
	})
}

// Read reads decrypted plaintext from the pipe.
func (cp *ClientCryptPipe) Read(b []byte) (int, error) {
	return cp.connRead.Read(b)
}

// Write writes plaintext that will be encrypted into an outbound record.
func (cp *ClientCryptPipe) Write(b []byte) (int, error) {
	select {
	case <-cp.closed:
		return 0, errors.New("exithandshake: pipe closed")
	default:
	}
	return cp.writeIn.Write(b)
}

// Close closes the pipe and the underlying connection.
func (cp *ClientCryptPipe) Close() error {
	cp.closeOnce.Do(func() {
		close(cp.closed)
	})
	cp.connRead.Close()
	cp.writeIn.Close()
	return cp.rawConn.Close()
}

// LocalAddr returns the underlying connection's local address.
func (cp *ClientCryptPipe) LocalAddr() net.Addr { return cp.rawConn.LocalAddr() }

// RemoteAddr returns the underlying connection's remote address.
func (cp *ClientCryptPipe) RemoteAddr() net.Addr { return cp.rawConn.RemoteAddr() }

// SetDeadline sets the underlying connection's deadline.
func (cp *ClientCryptPipe) SetDeadline(t time.Time) error { return cp.rawConn.SetDeadline(t) }

// SetReadDeadline sets the underlying connection's read deadline.
func (cp *ClientCryptPipe) SetReadDeadline(t time.Time) error {
	return cp.rawConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the underlying connection's write deadline.
func (cp *ClientCryptPipe) SetWriteDeadline(t time.Time) error {
	return cp.rawConn.SetWriteDeadline(t)
}

// Protocol returns "plain", matching Rust ClientExitCryptPipe::protocol().
func (cp *ClientCryptPipe) Protocol() string { return cp.protocol }

// RemoteAddrStr returns the underlying pipe's remote address string.
func (cp *ClientCryptPipe) RemoteAddrStr() string { return cp.remoteStr }

// SharedSecret returns the carried-through shared secret (usually nil for the
// X25519 path).
func (cp *ClientCryptPipe) SharedSecret() []byte { return cp.sharedSecret }

// Ensure ClientCryptPipe satisfies sillad.Pipe.
var _ sillad.Pipe = (*ClientCryptPipe)(nil)
