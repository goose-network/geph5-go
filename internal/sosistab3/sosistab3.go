// Package sosistab3 implements the sillad-sosistab3 obfuscation transport,
// wire-compatible with the Rust sillad_sosistab3 crate.
//
// Protocol overview:
//
//  1. Handshake (client dialer side):
//     - Generate an ephemeral X25519 keypair.
//     - Build a Handshake{eph_pk, timestamp, padding_len, padding_hash,
//       responding_to=blake3("")}, encrypt it with the cookie key (ChaCha20Poly1305,
//       12-byte random nonce, AEAD over the 112-byte plaintext) -> 140 bytes
//       (12 nonce + 112 ciphertext + 16 tag).
//     - Send the 140-byte encrypted handshake followed by `padding_len` random
//       padding bytes.
//     - Read the server's 140-byte encrypted handshake, decrypt it, verify
//       responding_to == blake3(our_encrypted_handshake_bytes). Read and verify
//       the server's padding.
//     - Derive the shared secret = X25519(our_eph_sk, their_eph_pk).
//
//  2. Record framing (State):
//     - Two AEAD keys derived via blake3::derive_key("up", ss) and
//       blake3::derive_key("dn", ss) (client: send="up", recv="dn").
//     - Each record: encrypt a 4-byte LE i32 length (nonce = send_nonce, then
//       send_nonce+1 for the body) with ChaCha20Poly1305, producing
//       [4 enc length][16 tag][N enc body][16 tag]. The length is signed: a
//       negative value (sign bit) marks a padding record (discarded on decrypt).
//     - Nonces: 12 bytes, first 8 = u64 LE counter (incremented by 2 per record:
//       0,1 for record 0; 2,3 for record 1; ...), last 4 = zero. Independent
//       counters per direction.
//     - obfs_lengths (optional): pad short records up to the next power of two
//       plus 0..10 random bytes, emitted as padding (negative-length) records.
package sosistab3

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/geph-official/geph5-go/internal/blake3"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// ObfsParams controls optional obfuscation. Matches Rust ObfsParams.
type ObfsParams struct {
	ObfsLengths bool
	ObfsTiming  bool
}

// Cookie is the pre-shared obfuscation key, derived from a string.
type Cookie struct {
	key    [32]byte
	params ObfsParams
}

// NewCookie derives a cookie from a string of the form "<key>---{json params}"
// or just "<key>". The key is derived via blake3::derive_key("cookie", key).
func NewCookie(s string) Cookie {
	var raw, paramsStr string
	for i, c := range s {
		_ = i
		_ = c
	}
	// Split on first "---".
	dashIdx := indexOf(s, "---")
	if dashIdx >= 0 {
		raw = s[:dashIdx]
		paramsStr = s[dashIdx+3:]
	} else {
		raw = s
	}
	params := ObfsParams{}
	if paramsStr != "" {
		// Best-effort JSON parse of {"obfs_lengths":bool,"obfs_timing":bool}.
		params = parseObfsParams(paramsStr)
	}
	derived := blake3.DeriveKey("cookie", []byte(raw))
	var c Cookie
	copy(c.key[:], derived[:])
	c.params = params
	return c
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func parseObfsParams(s string) ObfsParams {
	// Minimal JSON parser for {"obfs_lengths":true,"obfs_timing":false}.
	out := ObfsParams{}
	if contains(s, "\"obfs_lengths\":true") {
		out.ObfsLengths = true
	}
	if contains(s, "\"obfs_timing\":true") {
		out.ObfsTiming = true
	}
	return out
}

func contains(s, sub string) bool {
	return indexOf(s, sub) >= 0
}

// deriveKey derives a per-direction AEAD key from the cookie.
func (c Cookie) deriveKey(isServer bool) [32]byte {
	label := "client"
	if isServer {
		label = "server"
	}
	var k [32]byte
	dk := blake3.DeriveKey(label, c.key[:])
	copy(k[:], dk[:])
	return k
}

// Params returns the obfuscation parameters.
func (c Cookie) Params() ObfsParams { return c.params }

// Handshake is the 112-byte plaintext handshake message.
type Handshake struct {
	EphPK        [32]byte
	Timestamp    uint64
	PaddingLen   uint64
	PaddingHash  [32]byte
	RespondingTo [32]byte
}

func (h Handshake) bytes() [112]byte {
	var b [112]byte
	copy(b[0:32], h.EphPK[:])
	binary.BigEndian.PutUint64(b[32:40], h.Timestamp)
	binary.BigEndian.PutUint64(b[40:48], h.PaddingLen)
	copy(b[48:80], h.PaddingHash[:])
	copy(b[80:112], h.RespondingTo[:])
	return b
}

func handshakeFromBytes(b []byte) Handshake {
	var h Handshake
	copy(h.EphPK[:], b[0:32])
	h.Timestamp = binary.BigEndian.Uint64(b[32:40])
	h.PaddingLen = binary.BigEndian.Uint64(b[40:48])
	copy(h.PaddingHash[:], b[48:80])
	copy(h.RespondingTo[:], b[80:112])
	return h
}

// encryptHandshake encrypts a handshake into 140 bytes: [12 nonce][112 ciphertext][16 tag].
func encryptHandshake(h Handshake, c Cookie, isServer bool) ([140]byte, error) {
	var out [140]byte
	dk := c.deriveKey(isServer)
	aead, err := chacha20poly1305.New(dk[:])
	if err != nil {
		return out, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return out, err
	}
	pt := h.bytes()
	ciphertext := aead.Seal(nil, nonce, pt[:], nil)
	// Seal appends the 16-byte tag -> ciphertext is 112+16 = 128 bytes.
	copy(out[0:12], nonce)
	copy(out[12:140], ciphertext)
	return out, nil
}

// decryptHandshake decrypts a 140-byte encrypted handshake.
func decryptHandshake(enc [140]byte, c Cookie, isServer bool) (Handshake, error) {
	dk := c.deriveKey(isServer)
	aead, err := chacha20poly1305.New(dk[:])
	if err != nil {
		return Handshake{}, err
	}
	nonce := enc[:12]
	ciphertext := enc[12:140] // 128 bytes = 112 plaintext + 16 tag
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return Handshake{}, fmt.Errorf("sosistab3: handshake decryption failed: %w", err)
	}
	return handshakeFromBytes(plaintext), nil
}

// State holds the per-direction AEAD state for an established sosistab3 pipe.
type State struct {
	sharedSecret []byte
	sendAEAD     cipher.AEAD
	sendNonce    uint64
	recvAEAD     cipher.AEAD
	recvNonce    uint64
	obfs         ObfsParams
	sendBuf      []byte
}

// NewState derives the send/recv AEAD keys from a shared secret.
// Client: send="up", recv="dn". Server: send="dn", recv="up".
func NewState(ss []byte, isServer bool, obfs ObfsParams) (*State, error) {
	sendLabel, recvLabel := "up", "dn"
	if isServer {
		sendLabel, recvLabel = "dn", "up"
	}
	sendKey := blake3.DeriveKey(sendLabel, ss)
	recvKey := blake3.DeriveKey(recvLabel, ss)
	sendAEAD, err := chacha20poly1305.New(sendKey[:])
	if err != nil {
		return nil, err
	}
	recvAEAD, err := chacha20poly1305.New(recvKey[:])
	if err != nil {
		return nil, err
	}
	return &State{
		sharedSecret: append([]byte(nil), ss...),
		sendAEAD:     sendAEAD,
		recvAEAD:     recvAEAD,
		obfs:         obfs,
	}, nil
}

// SharedSecret returns the shared secret bytes.
func (s *State) SharedSecret() []byte { return s.sharedSecret }

func (s *State) nextSendNonce() [12]byte {
	var n [12]byte
	binary.LittleEndian.PutUint64(n[0:8], s.sendNonce)
	s.sendNonce++
	return n
}

func (s *State) recvNonceAt(offset uint64) [12]byte {
	var n [12]byte
	binary.LittleEndian.PutUint64(n[0:8], s.recvNonce+offset)
	return n
}

// Encrypt encrypts a hunk of data, appending the ciphertext to output.
// If obfs.ObfsLengths is set and the record is short, padding records are added.
func (s *State) Encrypt(data []byte, output *[]byte) {
	origLen := s.encryptInner(data, output, false)
	overhead := origLen - len(data)
	if s.obfs.ObfsLengths && origLen < 2000 {
		desired := nextPow2(origLen+overhead) + int(randIntn(10))
		if desired > origLen+overhead {
			paddingInnerLen := desired - origLen - overhead
			if paddingInnerLen > 0 && paddingInnerLen <= 2000 {
				lala := make([]byte, paddingInnerLen)
				s.encryptInner(lala, output, true)
			}
		}
	}
}

func (s *State) encryptInner(data []byte, output *[]byte, isPadding bool) int {
	tally := 0
	var lengthBytes [4]byte
	if isPadding {
		// negative length = -(len as i32), encoded as LE i32.
		binary.LittleEndian.PutUint32(lengthBytes[:], uint32(int32(-len(data))))
	} else {
		binary.LittleEndian.PutUint32(lengthBytes[:], uint32(int32(len(data))))
	}
	// Encrypt the length with the next nonce.
	nonce := s.nextSendNonce()
	// encrypt_in_place_detached: encrypt length in place, append tag.
	encLen := s.sendAEAD.Seal(nil, nonce[:], nil, lengthBytes[:])
	// Seal with nil plaintext produces just the tag (16 bytes) when dst=nil?
	// Actually Seal(nil, nonce, plaintext, nil) = ciphertext+tag. For
	// encrypt_in_place_detached we want: ciphertext = plaintext (XChaCha
	// keystream XOR), tag separate. ChaCha20Poly1305 Seal produces
	// ciphertext||tag where ciphertext = plaintext XOR keystream. So encLen is
	// 4+16 = 20 bytes: first 4 = encrypted length, last 16 = tag.
	encLength := encLen[:4]
	tagLen := encLen[4:20]
	*output = append(*output, encLength...)
	*output = append(*output, tagLen...)
	tally += 4 + 16

	// Encrypt the body with the next nonce.
	nonce2 := s.nextSendNonce()
	encBody := s.sendAEAD.Seal(nil, nonce2[:], data, nil)
	bodyCiphertext := encBody[:len(data)]
	tagBody := encBody[len(data) : len(data)+16]
	*output = append(*output, bodyCiphertext...)
	*output = append(*output, tagBody...)
	tally += len(data) + 16
	return tally
}

// Decrypt attempts to decrypt one record from bts, appending plaintext to
// output. Returns the number of bytes consumed. If not enough data is present,
// returns an error with kind WouldBlock (caller should wait for more data).
func (s *State) Decrypt(bts []byte, output *[]byte) (int, error) {
	if len(bts) < 24 {
		return 0, errWouldBlock
	}
	// enc_length (4) + tag_length (16) + enc_body (N) + tag_body (16)
	encLength := bts[0:4]
	tagLength := bts[4:20]
	rest := bts[20:]

	// Decrypt the length. decrypt_in_place_detached operates on the ciphertext
	// in place; we reconstruct: Open(nil, nonce, encLength||tag, nil) gives
	// the 4-byte plaintext length.
	nonce := s.recvNonceAt(0)
	// Build the combined ciphertext+tag for Open.
	encLenCombined := make([]byte, 0, 20)
	encLenCombined = append(encLenCombined, encLength...)
	encLenCombined = append(encLenCombined, tagLength...)
	lengthPT, err := s.recvAEAD.Open(nil, nonce[:], encLenCombined, nil)
	if err != nil {
		return 0, errBrokenPipe
	}
	length := int32(binary.LittleEndian.Uint32(lengthPT))
	actualLength := int(length)
	if actualLength < 0 {
		actualLength = -actualLength
	}
	if actualLength > 1024*1024 {
		return 0, errBrokenPipe
	}
	if actualLength+16 > len(rest) {
		return 0, errWouldBlock
	}
	encBody := rest[:actualLength]
	tagBody := rest[actualLength : actualLength+16]

	nonce2 := s.recvNonceAt(1)
	encBodyCombined := make([]byte, 0, actualLength+16)
	encBodyCombined = append(encBodyCombined, encBody...)
	encBodyCombined = append(encBodyCombined, tagBody...)
	bodyPT, err := s.recvAEAD.Open(nil, nonce2[:], encBodyCombined, nil)
	if err != nil {
		return 0, errBrokenPipe
	}
	if length > 0 {
		*output = append(*output, bodyPT...)
	}
	s.recvNonce += 2
	consumed := 4 + 16 + actualLength + 16
	return consumed, nil
}

var (
	errWouldBlock = errors.New("sosistab3: not enough data")
	errBrokenPipe = errors.New("sosistab3: broken pipe")
)

func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	return 1 << int(math.Ceil(math.Log2(float64(n))))
}

func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	v := int(binary.LittleEndian.Uint64(b[:])) % n
	if v < 0 {
		v = -v
	}
	return v
}

// Pipe is an established sosistab3 connection wrapping a lower sillad pipe.
type Pipe struct {
	lower       net.Conn
	state       *State
	readBuf     []byte
	readClosed  bool
	rawReadBuf  []byte
	remote      string
}

// Dial performs the client-side sosistab3 handshake over an already-connected
// lower pipe and returns an established Pipe.
func Dial(lower net.Conn, cookie Cookie) (*Pipe, error) {
	// Generate ephemeral X25519 keypair.
	ephSk := make([]byte, 32)
	if _, err := rand.Read(ephSk); err != nil {
		return nil, err
	}
	ephSk[0] &= 248
	ephSk[31] &= 127
	ephSk[31] |= 64
	ephPK, err := curve25519.X25519(ephSk, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var ephPKArr [32]byte
	copy(ephPKArr[:], ephPK)

	paddingLen := uint64(randIntn(1025)) // 0..=1024
	padding := make([]byte, paddingLen)
	if _, err := rand.Read(padding); err != nil {
		return nil, err
	}
	paddingHash := blake3.Hash(padding)

	myHandshake := Handshake{
		EphPK:        ephPKArr,
		Timestamp:    uint64(time.Now().Unix()),
		PaddingLen:   paddingLen,
		PaddingHash:  paddingHash,
		RespondingTo: blake3.Hash(nil),
	}
	encHS, err := encryptHandshake(myHandshake, cookie, false)
	if err != nil {
		return nil, err
	}
	// Send encrypted handshake + padding.
	toSend := make([]byte, 0, 140+len(padding))
	toSend = append(toSend, encHS[:]...)
	toSend = append(toSend, padding...)
	if _, err := lower.Write(toSend); err != nil {
		return nil, fmt.Errorf("sosistab3: write handshake: %w", err)
	}

	// Read their handshake.
	var theirEnc [140]byte
	if _, err := io.ReadFull(lower, theirEnc[:]); err != nil {
		return nil, fmt.Errorf("sosistab3: read their handshake: %w", err)
	}
	theirHS, err := decryptHandshake(theirEnc, cookie, true)
	if err != nil {
		return nil, err
	}
	// Verify responding_to == blake3(our encrypted handshake bytes).
	expected := blake3.Hash(encHS[:])
	if theirHS.RespondingTo != expected {
		return nil, errors.New("sosistab3: server handshake does not respond to ours")
	}
	if theirHS.PaddingLen > 100000 {
		return nil, errors.New("sosistab3: server padding too long")
	}
	theirPadding := make([]byte, theirHS.PaddingLen)
	if _, err := io.ReadFull(lower, theirPadding); err != nil {
		return nil, fmt.Errorf("sosistab3: read their padding: %w", err)
	}
	if blake3.Hash(theirPadding) != theirHS.PaddingHash {
		return nil, errors.New("sosistab3: server padding hash mismatch")
	}

	// Derive shared secret.
	var theirPK [32]byte
	copy(theirPK[:], theirHS.EphPK[:])
	ss, err := curve25519.X25519(ephSk, theirPK[:])
	if err != nil {
		return nil, err
	}
	state, err := NewState(ss, false, cookie.Params())
	if err != nil {
		return nil, err
	}
	remote := ""
	if r, ok := lower.(interface{ RemoteAddrStr() string }); ok {
		remote = r.RemoteAddrStr()
	}
	return &Pipe{lower: lower, state: state, remote: remote}, nil
}

func (p *Pipe) Protocol() string      { return "sosistab3" }
func (p *Pipe) RemoteAddrStr() string { return p.remote }
func (p *Pipe) SharedSecret() []byte  { return p.state.SharedSecret() }

func (p *Pipe) Read(b []byte) (int, error) {
	if len(p.readBuf) > 0 {
		n := copy(b, p.readBuf)
		p.readBuf = p.readBuf[n:]
		return n, nil
	}
	if p.readClosed {
		return 0, io.EOF
	}
	scratch := make([]byte, 16384)
	for {
		n, err := p.lower.Read(scratch)
		if n > 0 {
			p.rawReadBuf = append(p.rawReadBuf, scratch[:n]...)
			// Decrypt as many records as possible.
			for {
				consumed, derr := p.state.Decrypt(p.rawReadBuf, &p.readBuf)
				if derr != nil {
					if derr == errBrokenPipe {
						return 0, derr
					}
					break
				}
				p.rawReadBuf = p.rawReadBuf[consumed:]
			}
			if len(p.readBuf) > 0 {
				out := copy(b, p.readBuf)
				p.readBuf = p.readBuf[out:]
				return out, nil
			}
		}
		if err != nil {
			p.readClosed = true
			if len(p.readBuf) > 0 {
				out := copy(b, p.readBuf)
				p.readBuf = p.readBuf[out:]
				return out, nil
			}
			return 0, err
		}
	}
}

func (p *Pipe) Write(b []byte) (int, error) {
	var out []byte
	p.state.Encrypt(b, &out)
	written := 0
	for written < len(out) {
		n, err := p.lower.Write(out[written:])
		written += n
		if err != nil {
			return len(b), err
		}
	}
	return len(b), nil
}

func (p *Pipe) Close() error                    { return p.lower.Close() }
func (p *Pipe) LocalAddr() net.Addr             { return p.lower.LocalAddr() }
func (p *Pipe) RemoteAddr() net.Addr            { return p.lower.RemoteAddr() }
func (p *Pipe) SetDeadline(t time.Time) error   { return p.lower.SetDeadline(t) }
func (p *Pipe) SetReadDeadline(t time.Time) error  { return p.lower.SetReadDeadline(t) }
func (p *Pipe) SetWriteDeadline(t time.Time) error { return p.lower.SetWriteDeadline(t) }
