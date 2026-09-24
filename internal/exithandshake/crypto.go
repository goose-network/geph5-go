// Package exithandshake implements the client side of the geph5 client<->
// exit authentication handshake and the resulting encrypted pipe.
//
// Wire format (verified against the Rust source):
//
//  1. Client sends ClientHello (stdcode): { credentials: Bytes, crypt_hello: ClientCryptHello }
//     - ClientCryptHello::X25519(ephemeral_pubkey [32 bytes]) for full auth
//     - ClientCryptHello::SharedSecretChallenge(challenge [32 bytes]) for shared-secret auth
//     Both wrapped as length-prepended (4-byte BE u32) stdcode blobs.
//
//  2. Exit replies ExitHello (stdcode): { inner: ExitHelloInner, signature: ed25519 sig [64 bytes] }
//     - signature is over stdcode(&(client_hello, exit_hello.inner)) — the
//       concatenation of the ClientHello encoding and the ExitHelloInner encoding.
//     - ExitHelloInner::X25519(their_epk [32]) | SharedSecretResponse(mac [32]) | Reject(String)
//
//  3. For X25519: shared = DH(my_esk, their_epk); read_key = blake3::derive_key("e2c", shared);
//     write_key = blake3::derive_key("c2e", shared). The pipe is then wrapped in
//     ChaCha20Poly1305 record framing (see CryptPipe).
package exithandshake

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/geph-official/geph5-go/internal/blake3"
	"github.com/geph-official/geph5-go/internal/stdcode"
)

// ClientCryptHello is the client's ephemeral hello payload.
type ClientCryptHello struct {
	// X25519 holds the variant discriminant.
	Kind ClientCryptHelloKind
	// X25519Pub is the ephemeral X25519 public key (Kind == KindX25519).
	X25519Pub [32]byte
	// Challenge is the shared-secret challenge (Kind == KindSharedSecret).
	Challenge [32]byte
}

type ClientCryptHelloKind uint8

const (
	KindX25519 ClientCryptHelloKind = 0
	KindSharedSecret ClientCryptHelloKind = 1
)

// MarshalStdcode encodes ClientCryptHello as the externally-tagged enum
// ClientCryptHello { X25519([u8;32]), SharedSecretChallenge([u8;32]) }.
func (c *ClientCryptHello) MarshalStdcode() ([]byte, error) {
	e := stdcode.NewEncoder()
	switch c.Kind {
	case KindX25519:
		e.EncodeU32(0)
		e.EncodeRaw(c.X25519Pub[:])
	case KindSharedSecret:
		e.EncodeU32(1)
		e.EncodeRaw(c.Challenge[:])
	default:
		return nil, fmt.Errorf("exithandshake: invalid ClientCryptHello kind %d", c.Kind)
	}
	return e.Bytes(), nil
}

// ClientHello is the top-level client hello: { credentials: Vec<u8>, crypt_hello: ClientCryptHello }.
type ClientHello struct {
	Credentials []byte // stdcode-encoded credentials, or empty
	CryptHello  ClientCryptHello
}

// MarshalStdcode encodes ClientHello. Field order: credentials (bytes), then crypt_hello.
func (h *ClientHello) MarshalStdcode() ([]byte, error) {
	e := stdcode.NewEncoder()
	e.EncodeBytes(h.Credentials)
	helloBytes, err := h.CryptHello.MarshalStdcode()
	if err != nil {
		return nil, err
	}
	e.EncodeRaw(helloBytes)
	return e.Bytes(), nil
}

// ExitHelloInner is the exit's response payload.
type ExitHelloInner struct {
	Kind       ExitHelloInnerKind
	X25519Pub  [32]byte // Kind == InnerX25519
	MAC        [32]byte // Kind == InnerSharedSecretResponse
	RejectReason string // Kind == InnerReject
}

type ExitHelloInnerKind uint8

const (
	InnerX25519 ExitHelloInnerKind = 0
	InnerSharedSecretResponse ExitHelloInnerKind = 1
	InnerReject ExitHelloInnerKind = 2
)

// MarshalStdcode encodes ExitHelloInner as the externally-tagged enum
// ExitHelloInner { X25519([u8;32]), SharedSecretResponse([u8;32]), Reject(String) }.
// This is the inverse of UnmarshalStdcode and is used to reconstruct the
// stdcode((client_hello, exit_hello.inner)) blob that the exit signs.
func (i *ExitHelloInner) MarshalStdcode() ([]byte, error) {
	e := stdcode.NewEncoder()
	switch i.Kind {
	case InnerX25519:
		e.EncodeU32(0)
		e.EncodeRaw(i.X25519Pub[:])
	case InnerSharedSecretResponse:
		e.EncodeU32(1)
		e.EncodeRaw(i.MAC[:])
	case InnerReject:
		e.EncodeU32(2)
		e.EncodeString(i.RejectReason)
	default:
		return nil, fmt.Errorf("exithandshake: invalid ExitHelloInner kind %d", i.Kind)
	}
	return e.Bytes(), nil
}

// UnmarshalStdcode decodes ExitHelloInner (externally-tagged enum).
func (i *ExitHelloInner) UnmarshalStdcode(b []byte) error {
	d := stdcode.NewDecoder(b)
	idx, err := d.DecodeEnum()
	if err != nil {
		return err
	}
	switch idx {
	case 0:
		i.Kind = InnerX25519
		if err := d.NeedExact(32); err != nil {
			return err
		}
		copy(i.X25519Pub[:], d.RemainingBytes()[:32])
	case 1:
		i.Kind = InnerSharedSecretResponse
		if err := d.NeedExact(32); err != nil {
			return err
		}
		copy(i.MAC[:], d.RemainingBytes()[:32])
	case 2:
		i.Kind = InnerReject
		s, err := d.DecodeString()
		if err != nil {
			return err
		}
		i.RejectReason = s
	default:
		return fmt.Errorf("exithandshake: unknown ExitHelloInner variant %d", idx)
	}
	return nil
}

// ExitHello is { inner: ExitHelloInner, signature: [u8;64] }.
type ExitHello struct {
	Inner     ExitHelloInner
	Signature [64]byte
}

// UnmarshalStdcode decodes ExitHello.
func (h *ExitHello) UnmarshalStdcode(b []byte) error {
	d := stdcode.NewDecoder(b)
	// inner is an enum; we need to find where it ends. Decode by scanning: the
	// enum tag + payload, then the 64-byte signature follows. We decode inner
	// into a sub-slice by re-deriving its length.
	innerStart := d.Position()
	idx, err := d.DecodeEnum()
	if err != nil {
		return err
	}
	switch idx {
	case 0:
		if err := d.Skip(32); err != nil {
			return err
		}
	case 1:
		if err := d.Skip(32); err != nil {
			return err
		}
	case 2:
		if _, err := d.DecodeString(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("exithandshake: unknown inner variant %d", idx)
	}
	innerEnd := d.Position()
	// Re-decode inner from the sub-slice for its fields.
	if err := h.Inner.UnmarshalStdcode(b[innerStart:innerEnd]); err != nil {
		return err
	}
	// signature: 64 bytes
	if err := d.NeedExact(64); err != nil {
		return err
	}
	copy(h.Signature[:], d.RemainingBytes()[:64])
	return nil
}

// DeriveKeys performs X25519 ECDH and derives the two directional keys.
// readKey = blake3::derive_key("e2c", shared), writeKey = blake3::derive_key("c2e", shared).
func DeriveKeys(myEphemeralPriv, theirEphemeralPub [32]byte) (readKey, writeKey [32]byte) {
	shared, err := curve25519.X25519(myEphemeralPriv[:], theirEphemeralPub[:])
	if err != nil {
		panic(fmt.Sprintf("exithandshake: X25519 failed: %v", err))
	}
	readKey = blake3.DeriveKey("e2c", shared)
	writeKey = blake3.DeriveKey("c2e", shared)
	return
}

// NewEphemeralKey generates a new X25519 keypair.
func NewEphemeralKey() (priv, pub [32]byte, err error) {
	_, err = rand.Read(priv[:])
	if err != nil {
		return
	}
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return
	}
	copy(pub[:], pubBytes)
	return
}

// CryptPipe wraps a byte stream in ChaCha20Poly1305 record framing.
//
// Each record: 4-byte BE u32 length prefix + ciphertext. Ciphertext is
// ChaCha20Poly1305 with a 12-byte nonce = [counter_u64 LE][0x00;4], no AAD.
// Read and write directions use independent counters starting at 0.
type CryptPipe struct {
	rw       io.ReadWriteCloser
	readKey  [32]byte
	writeKey [32]byte
	readCtr  uint64
	writeCtr uint64
}

// NewCryptPipe wraps rw with the given directional keys.
func NewCryptPipe(rw io.ReadWriteCloser, readKey, writeKey [32]byte) (*CryptPipe, error) {
	return &CryptPipe{rw: rw, readKey: readKey, writeKey: writeKey}, nil
}

func nonceFor(counter uint64) [12]byte {
	var n [12]byte
	binary.LittleEndian.PutUint64(n[:8], counter)
	return n
}

// Write encrypts plaintext as one record and writes it.
func (p *CryptPipe) Write(plaintext []byte) error {
	aead, err := chacha20poly1305.New(p.writeKey[:])
	if err != nil {
		return err
	}
	nonce := nonceFor(p.writeCtr)
	p.writeCtr++
	ciphertext := aead.Seal(nil, nonce[:], plaintext, nil)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ciphertext)))
	if _, err := p.rw.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := p.rw.Write(ciphertext); err != nil {
		return err
	}
	return nil
}

// Read decrypts one record.
func (p *CryptPipe) Read() ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(p.rw, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > 100*1024 {
		return nil, fmt.Errorf("exithandshake: record too large: %d", n)
	}
	ciphertext := make([]byte, n)
	if _, err := io.ReadFull(p.rw, ciphertext); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(p.readKey[:])
	if err != nil {
		return nil, err
	}
	nonce := nonceFor(p.readCtr)
	p.readCtr++
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("exithandshake: decrypt failed: %w", err)
	}
	return plaintext, nil
}

// Close closes the underlying stream.
func (p *CryptPipe) Close() error { return p.rw.Close() }
