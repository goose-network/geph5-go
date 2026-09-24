// Package mizaru2 implements the Mizaru2 blind-signature token system, a
// port of the Rust crate at geph5/libraries/mizaru2.
//
// This file implements the RSABSSA-SHA256-PSS-Randomized blind RSA signature
// protocol (RFC 9474) directly with crypto/rsa, crypto/sha256, math/big, and
// crypto/rand. We do NOT use cloudflare/circl's blindsign/blindrsa package
// because it only ships SHA-384 variants; the geph5 protocol requires SHA-256
// with a 32-byte salt (blind-rsa-signatures v0.15.2 Options::new(Sha256,
// true, 32)). The EMSA-PSS encode/verify and blinding logic below is adapted
// from circl's hash-agnostic internal/common primitives, retargeted to
// SHA-256.
package mizaru2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
)

// rsaSaltLen is the PSS salt length used by the mizaru2 protocol: 32 bytes,
// matching blind-rsa-signatures Options::new(Hash::Sha256, true, 32).
const rsaSaltLen = 32

// BlindState holds the client-side state needed to finalize (unblind) a
// blind RSA signature: the encoded message EM produced during blinding and
// the inverse of the blinding factor r. It corresponds to brs::Secret.
type BlindState struct {
	encodedMsg []byte // EM = EMSA-PSS-ENCODE(msg, emBits, salt)
	rInv       *big.Int
}

// blindBlind generates a random blinding factor r in [1, N-1] together with
// its modular inverse. Mirrors circl common.GenerateBlindingFactor.
func generateBlindingFactor(random io.Reader, n *big.Int) (*big.Int, *big.Int, error) {
	if random == nil {
		random = rand.Reader
	}
	r, err := rand.Int(random, n)
	if err != nil {
		return nil, nil, err
	}
	if r.Sign() == 0 {
		r.SetInt64(1)
	}
	rInv := new(big.Int).ModInverse(r, n)
	if rInv == nil {
		return nil, nil, errors.New("mizaru2: invalid blinding factor (r not invertible)")
	}
	return r, rInv, nil
}

// mgf1XOR XORs out with the MGF1 mask generated from seed using the given
// hash. Mirrors RFC 8017 / PKCS#1 v2.1 MGF1.
func mgf1XOR(out []byte, h hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte
	done := 0
	for done < len(out) {
		h.Write(seed)
		h.Write(counter[:])
		digest = h.Sum(digest[:0])
		h.Reset()
		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		// increment big-endian 4-byte counter
		for i := 3; i >= 0; i-- {
			counter[i]++
			if counter[i] != 0 {
				break
			}
		}
	}
}

// emsaPSSEncode produces the EMSA-PSS encoding of mHash (already-hashed
// message) for a modulus of emBits bits, using the given salt. Returns EM of
// length ceil(emBits/8). Mirrors RFC 8017 Section 9.1.1 and circl
// common.emsaPSSEncode.
func emsaPSSEncode(mHash []byte, emBits int, salt []byte, h hash.Hash) ([]byte, error) {
	hLen := h.Size()
	sLen := len(salt)
	emLen := (emBits + 7) / 8

	if len(mHash) != hLen {
		return nil, errors.New("mizaru2: input not hashed with given hash")
	}
	if emLen < hLen+sLen+2 {
		return nil, errors.New("mizaru2: key size too small for PSS signature")
	}

	em := make([]byte, emLen)
	psLen := emLen - sLen - hLen - 2
	db := em[:psLen+1+sLen]
	h2 := em[psLen+1+sLen : emLen-1]

	// M' = 0x00*8 || mHash || salt ; H = Hash(M')
	var prefix [8]byte
	h.Write(prefix[:])
	h.Write(mHash)
	h.Write(salt)
	h2 = h.Sum(h2[:0])
	h.Reset()

	// DB = PS || 0x01 || salt
	db[psLen] = 0x01
	copy(db[psLen+1:], salt)

	// maskedDB = DB xor MGF1(H, len(DB))
	mgf1XOR(db, h, h2)

	// clear the top bits so 8*emLen - emBits high bits of EM[0] are zero
	db[0] &= byte(0xff) >> uint(8*emLen-emBits)

	// EM = maskedDB || H || 0xbc
	em[emLen-1] = 0xbc
	return em, nil
}

// emsaPSSVerify checks that em is a valid EMSA-PSS encoding of mHash for
// emBits bits and salt length sLen. Mirrors RFC 8017 Section 9.1.2 and circl
// common.emsaPSSVerify.
func emsaPSSVerify(mHash, em []byte, emBits, sLen int, h hash.Hash) error {
	hLen := h.Size()
	emLen := (emBits + 7) / 8
	if emLen != len(em) {
		return rsa.ErrVerification
	}
	if hLen != len(mHash) {
		return rsa.ErrVerification
	}
	if emLen < hLen+sLen+2 {
		return rsa.ErrVerification
	}
	if em[emLen-1] != 0xbc {
		return rsa.ErrVerification
	}
	db := em[:emLen-hLen-1]
	h2 := em[emLen-hLen-1 : emLen-1]
	bitMask := byte(0xff) >> uint(8*emLen-emBits)
	if em[0]&^bitMask != 0 {
		return rsa.ErrVerification
	}
	mgf1XOR(db, h, h2)
	db[0] &= bitMask
	psLen := emLen - hLen - sLen - 2
	for _, e := range db[:psLen] {
		if e != 0x00 {
			return rsa.ErrVerification
		}
	}
	if db[psLen] != 0x01 {
		return rsa.ErrVerification
	}
	salt := db[len(db)-sLen:]
	var prefix [8]byte
	h.Write(prefix[:])
	h.Write(mHash)
	h.Write(salt)
	h0 := h.Sum(nil)
	h.Reset()
	if subtle.ConstantTimeCompare(h0, h2) != 1 {
		return rsa.ErrVerification
	}
	return nil
}

// encodeMessageEMSAPSS hashes message with SHA-256 and applies EMSA-PSS
// encoding for the given modulus, using the supplied salt. Returns EM.
func encodeMessageEMSAPSS(message []byte, n *big.Int, salt []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(message)
	digest := h.Sum(nil)
	h.Reset()
	emBits := n.BitLen() - 1
	return emsaPSSEncode(digest, emBits, salt, h)
}

// rsaBlind performs the client-side Blind operation of RSABSSA-SHA256-PSS-
// Randomized. It returns the blinded message (k bytes) and the BlindState
// needed to finalize. msg is used directly (no Prepare prefix), matching
// mizaru2's `blind(rng, msg, false, ...)`.
func rsaBlind(random io.Reader, pub *rsa.PublicKey, msg []byte) ([]byte, BlindState, error) {
	if random == nil {
		random = rand.Reader
	}
	salt := make([]byte, rsaSaltLen)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, BlindState{}, err
	}
	r, rInv, err := generateBlindingFactor(random, pub.N)
	if err != nil {
		return nil, BlindState{}, err
	}

	encodedMsg, err := encodeMessageEMSAPSS(msg, pub.N, salt)
	if err != nil {
		return nil, BlindState{}, err
	}
	m := new(big.Int).SetBytes(encodedMsg)

	// RFC 9474 coprimality check: reject encoded messages sharing a factor
	// with the modulus.
	if new(big.Int).GCD(nil, nil, m, pub.N).Cmp(bigOne) != 0 {
		return nil, BlindState{}, errors.New("mizaru2: encoded message not coprime to modulus")
	}

	bigE := big.NewInt(int64(pub.E))
	x := new(big.Int).Exp(r, bigE, pub.N)
	z := new(big.Int).Set(m)
	z.Mul(z, x)
	z.Mod(z, pub.N)

	kLen := (pub.N.BitLen() + 7) / 8
	blindedMsg := make([]byte, kLen)
	z.FillBytes(blindedMsg)

	return blindedMsg, BlindState{encodedMsg: encodedMsg, rInv: rInv}, nil
}

// rsaBlindSign performs the signer-side BlindSign operation: s = z^d mod N,
// with CRT fault-attack checking and blinding for side-channel resistance.
// Returns the blinded signature (k bytes).
func rsaBlindSign(random io.Reader, priv *rsa.PrivateKey, blindedMsg []byte) ([]byte, error) {
	kLen := (priv.N.BitLen() + 7) / 8
	if len(blindedMsg) != kLen {
		return nil, errors.New("mizaru2: unexpected blinded message size")
	}
	z := new(big.Int).SetBytes(blindedMsg)
	if z.Cmp(priv.N) > 0 {
		return nil, errors.New("mizaru2: invalid blinded message length")
	}

	s, err := rsaDecryptBlinded(random, priv, z)
	if err != nil {
		return nil, err
	}
	blindSig := make([]byte, kLen)
	s.FillBytes(blindSig)
	return blindSig, nil
}

// rsaDecryptBlinded computes z^d mod N with blinding and a CRT consistency
// check (m^e == z). Mirrors circl common.DecryptAndCheck + decrypt.
func rsaDecryptBlinded(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (*big.Int, error) {
	if c.Cmp(priv.N) > 0 {
		return nil, rsa.ErrDecryption
	}
	if priv.N.Sign() == 0 {
		return nil, rsa.ErrDecryption
	}

	var ir *big.Int
	origC := c
	if random != nil {
		ir = new(big.Int)
		var r *big.Int
		for {
			var err error
			r, err = rand.Int(random, priv.N)
			if err != nil {
				return nil, err
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			if ir.ModInverse(r, priv.N); ir != nil {
				break
			}
		}
		rpowe := new(big.Int).Exp(r, big.NewInt(int64(priv.E)), priv.N)
		cBlind := new(big.Int).Set(c)
		cBlind.Mul(cBlind, rpowe)
		cBlind.Mod(cBlind, priv.N)
		c = cBlind
	}

	m := new(big.Int).Exp(c, priv.D, priv.N)
	if ir != nil {
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}

	// Fault-attack check: m^e mod N must equal the original (unblinded)
	// ciphertext. After unblinding, m = origC^d mod N, so m^e == origC.
	check := new(big.Int).Exp(m, big.NewInt(int64(priv.E)), priv.N)
	if origC.Cmp(check) != 0 {
		return nil, errors.New("mizaru2: rsa internal error (decryption check failed)")
	}
	return m, nil
}

// rsaFinalize performs the client-side Finalize (unblind) operation:
// sig = rInv * blindedSig mod N, then verifies that sig^e mod N equals the
// encoded message EM stored in the blind state. Returns the unblinded
// signature (k bytes).
func rsaFinalize(pub *rsa.PublicKey, state BlindState, blindedSig []byte) ([]byte, error) {
	kLen := (pub.N.BitLen() + 7) / 8
	if len(blindedSig) != kLen {
		return nil, errors.New("mizaru2: unexpected blinded signature size")
	}
	z := new(big.Int).SetBytes(blindedSig)
	s := new(big.Int).Set(state.rInv)
	s.Mul(s, z)
	s.Mod(s, pub.N)

	sig := make([]byte, kLen)
	s.FillBytes(sig)

	// Verify the unblinded signature against the stored encoded message:
	// sig^e mod N must equal OS2IP(EM).
	if err := verifyBlindSignature(pub, state.encodedMsg, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// verifyBlindSignature checks that sig^e mod N equals the encoded message
// (as an integer). Mirrors circl common.VerifyBlindSignature.
func verifyBlindSignature(pub *rsa.PublicKey, encodedMsg, sig []byte) error {
	kLen := (pub.N.BitLen() + 7) / 8
	if len(sig) != kLen {
		return rsa.ErrVerification
	}
	m := new(big.Int).SetBytes(encodedMsg)
	bigSig := new(big.Int).SetBytes(sig)
	if bigSig.Cmp(pub.N) >= 0 {
		return rsa.ErrVerification
	}
	c := new(big.Int).Exp(bigSig, big.NewInt(int64(pub.E)), pub.N)
	if subtle.ConstantTimeCompare(m.Bytes(), c.Bytes()) == 1 {
		return nil
	}
	return rsa.ErrVerification
}

// rsaVerify performs the standard RSASSA-PSS verification of an unblinded
// signature over msg, using SHA-256 and a 32-byte salt. This is the public
// verification that any party with the RSA public key can perform.
func rsaVerify(pub *rsa.PublicKey, msg, sig []byte) error {
	kLen := (pub.N.BitLen() + 7) / 8
	if len(sig) != kLen {
		return rsa.ErrVerification
	}
	s := new(big.Int).SetBytes(sig)
	if s.Cmp(pub.N) >= 0 {
		return rsa.ErrVerification
	}
	m := new(big.Int).Exp(s, big.NewInt(int64(pub.E)), pub.N)
	emBits := pub.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	if m.BitLen() > emLen*8 {
		return rsa.ErrVerification
	}
	em := m.FillBytes(make([]byte, emLen))
	h := sha256.New()
	h.Write(msg)
	digest := h.Sum(nil)
	h.Reset()
	return emsaPSSVerify(digest, em, emBits, rsaSaltLen, h)
}

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

// errInvalidMerkleProof is returned when a Merkle membership proof fails.
var errInvalidMerkleProof = errors.New("mizaru2: merkle proof failed")
