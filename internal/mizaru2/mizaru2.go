package mizaru2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/geph-official/geph5-go/internal/blake3"
	"github.com/geph-official/geph5-go/internal/stdcode"
)

// KeyCount is the number of per-epoch RSA subkeys in a full Mizaru secret
// key, matching the Rust KEY_COUNT = 65536. The epoch selects which subkey
// signs a given token.
const KeyCount = 65536

// KeyBits is the RSA modulus size in bits (RSA-2048).
const KeyBits = 2048

// Hash is a 32-byte BLAKE3 digest, matching blake3::Hash.
type Hash [32]byte

// CurrentEpoch returns the current Mizaru epoch: floor(unix_seconds / 86400)
// as a uint16. Matches Rust current_epoch().
func CurrentEpoch() uint16 {
	return uint16(time.Now().Unix() / 86400)
}

// UnixToEpoch converts a Unix timestamp (seconds) to its Mizaru epoch.
// Matches Rust unix_to_epoch().
func UnixToEpoch(unix uint64) uint16 {
	return uint16(unix / 86400)
}

// ClientToken is a 32-byte random token the client asks the broker to blind-
// sign. Matches Rust ClientToken([u8; 32]).
type ClientToken [32]byte

// Random returns a ClientToken filled with cryptographically random bytes.
// Matches Rust ClientToken::random().
func RandomToken() ClientToken {
	var t ClientToken
	if _, err := rand.Read(t[:]); err != nil {
		panic("mizaru2: crypto/rand failed: " + err.Error())
	}
	return t
}

// AsBytes returns the raw 32 bytes of the token.
func (t ClientToken) AsBytes() *[32]byte {
	return (*[32]byte)(&t)
}

// Blind blinds this token against the given RSA public key, returning the
// blinded message (to send to the signer) and the BlindState (secret) needed
// to unblind the resulting signature. Matches Rust ClientToken::blind.
func (t ClientToken) Blind(pub *rsa.PublicKey) (blindedMsg []byte, secret BlindState, err error) {
	return rsaBlind(rand.Reader, pub, t[:])
}

// BlindWith is like Blind but accepts an explicit randomness source (useful
// for testing).
func (t ClientToken) BlindWith(random interface{ Read([]byte) (int, error) }, pub *rsa.PublicKey) ([]byte, BlindState, error) {
	return rsaBlind(random, pub, t[:])
}

// ----------------------------------------------------------------------------
// RSA key (de)serialization helpers — PKCS#1 DER, matching Rust
// rsa::pkcs1::EncodeRsaPublicKey / SecretKey::to_der / from_der.
// ----------------------------------------------------------------------------

// publicKeyToPKCS1DER encodes an RSA public key as PKCS#1 DER
// (RSAPublicKey ASN.1), matching Rust to_public_key().to_pkcs1_der().
func publicKeyToPKCS1DER(pub *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKCS1PublicKey(pub), nil
}

// pkcs1DERToPublicKey decodes a PKCS#1 DER RSA public key.
func pkcs1DERToPublicKey(der []byte) (*rsa.PublicKey, error) {
	return x509.ParsePKCS1PublicKey(der)
}

// ParsePKCS1PublicKey decodes a PKCS#1 DER RSA public key (exported wrapper
// around pkcs1DERToPublicKey for use by the auth client).
func ParsePKCS1PublicKey(der []byte) (*rsa.PublicKey, error) {
	return pkcs1DERToPublicKey(der)
}

// privateKeyToPKCS1DER encodes an RSA private key as PKCS#1 DER.
func privateKeyToPKCS1DER(priv *rsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS1PrivateKey(priv), nil
}

// pkcs1DERToPrivateKey decodes a PKCS#1 DER RSA private key.
func pkcs1DERToPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(der)
}

// ----------------------------------------------------------------------------
// Merkle tree.
//
// leaf  = blake3::hash(pkcs1_der_bytes_of_rsa_pubkey)
// internal = blake3::keyed_hash(left, right)
// The public key of the Mizaru scheme is the Merkle root (a blake3 Hash).
// ----------------------------------------------------------------------------

// buildMerkleTree builds all levels of the Merkle tree from the leaf hashes
// (one per subkey) and returns them. levels[0] is the leaves, levels[len-1]
// is the single-element root level. Matches the Rust construction.
func buildMerkleTree(leaves []Hash) [][]Hash {
	tree := make([][]Hash, 0, 1)
	tree = append(tree, leaves)
	for len(tree[len(tree)-1]) > 1 {
		last := tree[len(tree)-1]
		next := make([]Hash, len(last)/2)
		for i := range next {
			next[i] = blake3.KeyedHash(last[2*i], last[2*i+1][:])
		}
		tree = append(tree, next)
	}
	return tree
}

// merkleSibling returns the index of the sibling of node i within a level.
// Matches Rust sibling(i) = i/2*2 + ((i+1) % 2).
func merkleSibling(i int) int {
	return i/2*2 + ((i + 1) % 2)
}

// merkleBranch returns the Merkle authentication branch for the leaf at the
// given index, i.e. the sibling hash at each level from the leaves up to
// (but not including) the root. Matches Rust SecretKey::merkle_branch.
func merkleBranch(tree [][]Hash, idx uint16) []Hash {
	branch := make([]Hash, 0, len(tree)-1)
	i := int(idx)
	for level := 0; level < len(tree)-1; level++ {
		branch = append(branch, tree[level][merkleSibling(i)])
		i >>= 1
	}
	return branch
}

// VerifyMember verifies a Merkle membership proof: that the subkey whose
// PKCS#1 DER bytes are `subkeyDER` is the epoch-th leaf under the given root,
// using the authentication branch. Matches Rust PublicKey::verify_member.
//
//	acc = blake3::hash(subkey)
//	for i, h in branch:
//	    if (epoch >> i) & 1 == 0: acc = keyed_hash(acc, h)
//	    else:                    acc = keyed_hash(h, acc)
//	check acc == root
func VerifyMember(epoch uint16, subkeyDER []byte, branch []Hash, root Hash) error {
	acc := blake3.Hash(subkeyDER)
	for i, h := range branch {
		if (epoch>>uint(i))&1 == 0 {
			acc = blake3.KeyedHash(acc, h[:])
		} else {
			acc = blake3.KeyedHash(h, acc[:])
		}
	}
	if acc != root {
		return errInvalidMerkleProof
	}
	return nil
}

// ----------------------------------------------------------------------------
// Public key (Mizaru mode): the Merkle root.
// ----------------------------------------------------------------------------

// PublicKey is the Merkle-root public key (32-byte blake3 Hash). Matches
// Rust PublicKey(blake3::Hash).
type PublicKey struct {
	Root Hash
}

// FromBytes constructs a PublicKey from a 32-byte root.
func PublicKeyFromBytes(b [32]byte) PublicKey { return PublicKey{Root: b} }

// ToBytes returns the 32-byte root.
func (p PublicKey) ToBytes() [32]byte { return p.Root }

// BlindVerify verifies an unblinded Mizaru signature against this public key:
// first the Merkle membership proof (that used_key is the epoch-th subkey),
// then the RSA-PSS signature over the token. Matches Rust
// PublicKey::blind_verify.
func (p PublicKey) BlindVerify(token ClientToken, sig *UnblindedSignature) error {
	if err := VerifyMember(sig.Epoch, sig.UsedKey, sig.MerkleBranch, p.Root); err != nil {
		return err
	}
	pub, err := pkcs1DERToPublicKey(sig.UsedKey)
	if err != nil {
		return err
	}
	return rsaVerify(pub, token[:], sig.UnblindedSig)
}

// ----------------------------------------------------------------------------
// Secret key (Mizaru mode): 65536 RSA subkeys + their Merkle tree.
// ----------------------------------------------------------------------------

// SecretKey holds the per-epoch RSA private keys (as PKCS#1 DER) and the
// precomputed Merkle tree. Matches Rust SecretKey.
type SecretKey struct {
	rsaKeysDER  [][]byte
	merkleTree  [][]Hash
}

// GenerateSecretKey generates a full Mizaru secret key with KeyCount RSA-2048
// subkeys and builds the Merkle tree. This is expensive (65536 keygens) and
// intended for the broker; tests should use GenerateSecretKeyN or the
// single-key mode. Matches Rust SecretKey::generate.
func GenerateSecretKey(name string) *SecretKey {
	return generateSecretKeyN(name, KeyCount)
}

// GenerateSecretKeyN generates a Mizaru secret key with n subkeys. n must be
// a power of two (and <= KeyCount for the epoch indexing to be meaningful).
// Provided for tests that want a small tree.
func GenerateSecretKeyN(name string, n int) *SecretKey {
	return generateSecretKeyN(name, n)
}

func generateSecretKeyN(name string, n int) *SecretKey {
	if n < 1 {
		panic("mizaru2: must generate at least 1 subkey")
	}
	rsaKeys := make([]*rsa.PrivateKey, n)
	for i := 0; i < n; i++ {
		k, err := rsa.GenerateKey(rand.Reader, KeyBits)
		if err != nil {
			panic("mizaru2: rsa keygen failed: " + err.Error())
		}
		rsaKeys[i] = k
	}
	leaves := make([]Hash, n)
	for i, k := range rsaKeys {
		der, err := publicKeyToPKCS1DER(&k.PublicKey)
		if err != nil {
			panic("mizaru2: pkcs1 encode failed: " + err.Error())
		}
		leaves[i] = blake3.Hash(der)
	}
	tree := buildMerkleTree(leaves)

	keysDER := make([][]byte, n)
	for i, k := range rsaKeys {
		der, err := privateKeyToPKCS1DER(k)
		if err != nil {
			panic("mizaru2: pkcs1 encode failed: " + err.Error())
		}
		keysDER[i] = der
	}
	return &SecretKey{rsaKeysDER: keysDER, merkleTree: tree}
}

// ToPublicKey returns the Merkle-root public key. Matches Rust
// SecretKey::to_public_key.
func (s *SecretKey) ToPublicKey() PublicKey {
	last := s.merkleTree[len(s.merkleTree)-1]
	return PublicKey{Root: last[0]}
}

// GetSubkey returns the RSA private key for the given epoch. Matches Rust
// SecretKey::get_subkey.
func (s *SecretKey) GetSubkey(epoch uint16) (*rsa.PrivateKey, error) {
	return pkcs1DERToPrivateKey(s.rsaKeysDER[int(epoch)])
}

// GetSubkeyPublicKey returns the RSA public key for the given epoch.
func (s *SecretKey) GetSubkeyPublicKey(epoch uint16) (*rsa.PublicKey, error) {
	priv, err := s.GetSubkey(epoch)
	if err != nil {
		return nil, err
	}
	return &priv.PublicKey, nil
}

// MerkleBranch returns the authentication branch for the epoch-th leaf.
func (s *SecretKey) MerkleBranch(epoch uint16) []Hash {
	return merkleBranch(s.merkleTree, epoch)
}

// BlindSign blind-signs a blinded token with the epoch-th subkey, returning
// the BlindedSignature (including the used subkey's PKCS#1 DER and the
// Merkle branch). Matches Rust SecretKey::blind_sign.
func (s *SecretKey) BlindSign(epoch uint16, blinded *BlindedClientToken) (*BlindedSignature, error) {
	priv, err := s.GetSubkey(epoch)
	if err != nil {
		return nil, err
	}
	bareSig, err := rsaBlindSign(rand.Reader, priv, blinded.Bytes)
	if err != nil {
		return nil, err
	}
	usedKey, err := publicKeyToPKCS1DER(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &BlindedSignature{
		Epoch:        epoch,
		UsedKey:      usedKey,
		MerkleBranch: s.MerkleBranch(epoch),
		BlindedSig:   bareSig,
	}, nil
}

// ----------------------------------------------------------------------------
// Single-key mode (no Merkle tree).
// ----------------------------------------------------------------------------

// SingleSecretKey holds a single RSA private key (PKCS#1 DER). Matches Rust
// SingleSecretKey.
type SingleSecretKey struct {
	rsaKeyDER []byte
}

// GenerateSingleSecretKey generates a single RSA-2048 keypair. Matches Rust
// SingleSecretKey::generate.
func GenerateSingleSecretKey(name string) *SingleSecretKey {
	k, err := rsa.GenerateKey(rand.Reader, KeyBits)
	if err != nil {
		panic("mizaru2: rsa keygen failed: " + err.Error())
	}
	der, err := privateKeyToPKCS1DER(k)
	if err != nil {
		panic("mizaru2: pkcs1 encode failed: " + err.Error())
	}
	return &SingleSecretKey{rsaKeyDER: der}
}

// GetKey returns the underlying RSA private key. Matches Rust
// SingleSecretKey::get_key.
func (s *SingleSecretKey) GetKey() (*rsa.PrivateKey, error) {
	return pkcs1DERToPrivateKey(s.rsaKeyDER)
}

// ToPublicKey returns the matching single public key. Matches Rust
// SingleSecretKey::to_public_key.
func (s *SingleSecretKey) ToPublicKey() (*SinglePublicKey, error) {
	priv, err := s.GetKey()
	if err != nil {
		return nil, err
	}
	der, err := publicKeyToPKCS1DER(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &SinglePublicKey{DER: der}, nil
}

// BlindSign blind-signs a blinded token with the single key. Matches Rust
// SingleSecretKey::blind_sign.
func (s *SingleSecretKey) BlindSign(blinded *BlindedClientToken) (*SingleBlindedSignature, error) {
	priv, err := s.GetKey()
	if err != nil {
		return nil, err
	}
	bareSig, err := rsaBlindSign(rand.Reader, priv, blinded.Bytes)
	if err != nil {
		return nil, err
	}
	usedKey, err := publicKeyToPKCS1DER(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &SingleBlindedSignature{UsedKey: usedKey, BlindedSig: bareSig}, nil
}

// SinglePublicKey is the public half of a SingleSecretKey: the RSA public
// key as PKCS#1 DER. Matches Rust SinglePublicKey(Vec<u8>).
type SinglePublicKey struct {
	DER []byte
}

// FromDER constructs a SinglePublicKey from PKCS#1 DER bytes.
func SinglePublicKeyFromDER(der []byte) *SinglePublicKey {
	return &SinglePublicKey{DER: append([]byte(nil), der...)}
}

// ToDER returns the DER-encoded RSA public key.
func (p *SinglePublicKey) ToDER() []byte { return p.DER }

// Inner returns the parsed RSA public key. Matches Rust
// SinglePublicKey::inner.
func (p *SinglePublicKey) Inner() (*rsa.PublicKey, error) {
	return pkcs1DERToPublicKey(p.DER)
}

// BlindVerify verifies an unblinded single-key signature over the token.
// Matches Rust SinglePublicKey::blind_verify.
func (p *SinglePublicKey) BlindVerify(token ClientToken, sig *SingleUnblindedSignature) error {
	pub, err := p.Inner()
	if err != nil {
		return err
	}
	return rsaVerify(pub, token[:], sig.UnblindedSig)
}

// ----------------------------------------------------------------------------
// Wire types.
// ----------------------------------------------------------------------------

// BlindedClientToken is the blinded message sent from client to signer.
// Matches Rust BlindedClientToken(Vec<u8>). It is a raw byte buffer (not
// stdcode-serialized on its own; it flows inside the blind protocol).
type BlindedClientToken struct {
	Bytes []byte
}

// SingleBlindedSignature is a blinded signature from a SingleSecretKey.
// Matches Rust SingleBlindedSignature { used_key, blinded_sig }.
type SingleBlindedSignature struct {
	UsedKey   []byte // PKCS#1 DER of the signing RSA public key
	BlindedSig []byte
}

// Unblind unblinds a single-key blinded signature using the blind state
// (secret) and the original token. Matches Rust SingleBlindedSignature::unblind.
func (b *SingleBlindedSignature) Unblind(secret BlindState, msg ClientToken) (*SingleUnblindedSignature, error) {
	pub, err := pkcs1DERToPublicKey(b.UsedKey)
	if err != nil {
		return nil, err
	}
	unblinded, err := rsaFinalize(pub, secret, b.BlindedSig)
	if err != nil {
		return nil, err
	}
	_ = msg // msg is already embedded in the blind state's encoded message
	return &SingleUnblindedSignature{UnblindedSig: unblinded}, nil
}

// SingleUnblindedSignature is the final, unblinded single-key signature.
// Matches Rust SingleUnblindedSignature { unblinded_sig }.
type SingleUnblindedSignature struct {
	UnblindedSig []byte
}

// BlindedSignature is a Mizaru-mode blinded signature returned by the
// signer. Matches Rust BlindedSignature { epoch, used_key, merkle_branch,
// blinded_sig }. Serialized via STDCODE on the wire to the broker.
type BlindedSignature struct {
	Epoch        uint16
	UsedKey      []byte // PKCS#1 DER of the epoch's RSA public key
	MerkleBranch []Hash
	BlindedSig   []byte
}

// Unblind unblinds a Mizaru blinded signature using the blind state (secret)
// and the original token, producing an UnblindedSignature. Matches Rust
// BlindedSignature::unblind.
func (b *BlindedSignature) Unblind(secret BlindState, msg ClientToken) (*UnblindedSignature, error) {
	pub, err := pkcs1DERToPublicKey(b.UsedKey)
	if err != nil {
		return nil, err
	}
	unblinded, err := rsaFinalize(pub, secret, b.BlindedSig)
	if err != nil {
		return nil, err
	}
	_ = msg
	return &UnblindedSignature{
		Epoch:        b.Epoch,
		UsedKey:      b.UsedKey,
		MerkleBranch: b.MerkleBranch,
		UnblindedSig: unblinded,
	}, nil
}

// UnblindedSignature is the final, unblinded Mizaru signature. Matches Rust
// UnblindedSignature { epoch, used_key, merkle_branch, unblinded_sig }.
// Serialized via STDCODE on the wire to the broker.
type UnblindedSignature struct {
	Epoch        uint16
	UsedKey      []byte
	MerkleBranch []Hash
	UnblindedSig []byte
}

// ----------------------------------------------------------------------------
// STDCODE (bincode varint) serialization for the wire types. Matches the
// Rust serde + stdcode encoding of the corresponding structs.
// ----------------------------------------------------------------------------

// MarshalStdcode encodes a BlindedSignature as stdcode (bincode varint):
// epoch:u16, used_key:Vec<u8>, merkle_branch:Vec<Hash>, blinded_sig:Vec<u8>.
func (b *BlindedSignature) MarshalStdcode() ([]byte, error) {
	enc := stdcode.NewEncoder()
	enc.EncodeU16(b.Epoch)
	enc.EncodeBytes(b.UsedKey)
	enc.EncodeSeqLen(len(b.MerkleBranch))
	for _, h := range b.MerkleBranch {
		enc.EncodeRaw(h[:])
	}
	enc.EncodeBytes(b.BlindedSig)
	return enc.Bytes(), nil
}

// UnmarshalStdcode decodes a BlindedSignature from stdcode bytes.
func (b *BlindedSignature) UnmarshalStdcode(data []byte) error {
	dec := stdcode.NewDecoder(data)
	epoch, err := dec.DecodeU16()
	if err != nil {
		return err
	}
	usedKey, err := dec.DecodeBytes()
	if err != nil {
		return err
	}
	n, err := dec.DecodeSeqLen()
	if err != nil {
		return err
	}
	branch := make([]Hash, n)
	for i := 0; i < n; i++ {
		hBytes, err := dec.DecodeFixedBytes(32)
		if err != nil {
			return err
		}
		copy(branch[i][:], hBytes)
	}
	blindedSig, err := dec.DecodeBytes()
	if err != nil {
		return err
	}
	if !dec.EOF() {
		return stdcode.ErrTrailing
	}
	b.Epoch = epoch
	b.UsedKey = usedKey
	b.MerkleBranch = branch
	b.BlindedSig = blindedSig
	return nil
}

// MarshalStdcode encodes an UnblindedSignature as stdcode.
func (u *UnblindedSignature) MarshalStdcode() ([]byte, error) {
	enc := stdcode.NewEncoder()
	enc.EncodeU16(u.Epoch)
	enc.EncodeBytes(u.UsedKey)
	enc.EncodeSeqLen(len(u.MerkleBranch))
	for _, h := range u.MerkleBranch {
		enc.EncodeRaw(h[:])
	}
	enc.EncodeBytes(u.UnblindedSig)
	return enc.Bytes(), nil
}

// UnmarshalStdcode decodes an UnblindedSignature from stdcode bytes.
func (u *UnblindedSignature) UnmarshalStdcode(data []byte) error {
	dec := stdcode.NewDecoder(data)
	epoch, err := dec.DecodeU16()
	if err != nil {
		return err
	}
	usedKey, err := dec.DecodeBytes()
	if err != nil {
		return err
	}
	n, err := dec.DecodeSeqLen()
	if err != nil {
		return err
	}
	branch := make([]Hash, n)
	for i := 0; i < n; i++ {
		hBytes, err := dec.DecodeFixedBytes(32)
		if err != nil {
			return err
		}
		copy(branch[i][:], hBytes)
	}
	unblindedSig, err := dec.DecodeBytes()
	if err != nil {
		return err
	}
	if !dec.EOF() {
		return stdcode.ErrTrailing
	}
	u.Epoch = epoch
	u.UsedKey = usedKey
	u.MerkleBranch = branch
	u.UnblindedSig = unblindedSig
	return nil
}

// MarshalStdcode encodes a SingleBlindedSignature as stdcode.
func (b *SingleBlindedSignature) MarshalStdcode() ([]byte, error) {
	enc := stdcode.NewEncoder()
	enc.EncodeBytes(b.UsedKey)
	enc.EncodeBytes(b.BlindedSig)
	return enc.Bytes(), nil
}

// UnmarshalStdcode decodes a SingleBlindedSignature from stdcode bytes.
func (b *SingleBlindedSignature) UnmarshalStdcode(data []byte) error {
	dec := stdcode.NewDecoder(data)
	usedKey, err := dec.DecodeBytes()
	if err != nil {
		return err
	}
	blindedSig, err := dec.DecodeBytes()
	if err != nil {
		return err
	}
	if !dec.EOF() {
		return stdcode.ErrTrailing
	}
	b.UsedKey = usedKey
	b.BlindedSig = blindedSig
	return nil
}

// MarshalStdcode encodes a SingleUnblindedSignature as stdcode.
func (u *SingleUnblindedSignature) MarshalStdcode() ([]byte, error) {
	enc := stdcode.NewEncoder()
	enc.EncodeBytes(u.UnblindedSig)
	return enc.Bytes(), nil
}

// UnmarshalStdcode decodes a SingleUnblindedSignature from stdcode bytes.
func (u *SingleUnblindedSignature) UnmarshalStdcode(data []byte) error {
	dec := stdcode.NewDecoder(data)
	unblindedSig, err := dec.DecodeBytes()
	if err != nil {
		return err
	}
	if !dec.EOF() {
		return stdcode.ErrTrailing
	}
	u.UnblindedSig = unblindedSig
	return nil
}

// ErrInvalidMerkleProof is the sentinel returned for a failed Merkle proof.
var ErrInvalidMerkleProof = errInvalidMerkleProof
