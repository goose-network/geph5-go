package mizaru2

import (
	"bytes"
	"testing"
	"time"
)

// TestSingleBlindSignAndVerify exercises the full single-key blind RSA
// round trip: generate a keypair, blind a random token, blind-sign, unblind,
// and verify. Mirrors the Rust test_single_blind_sign_and_verify.
func TestSingleBlindSignAndVerify(t *testing.T) {
	sk := GenerateSingleSecretKey("test_single_blind_sign_and_verify")
	pk, err := sk.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	rsaPub, err := pk.Inner()
	if err != nil {
		t.Fatalf("pk.Inner: %v", err)
	}
	token := RandomToken()

	blindedMsg, secret, err := token.Blind(rsaPub)
	if err != nil {
		t.Fatalf("Blind: %v", err)
	}

	bsig, err := sk.BlindSign(&BlindedClientToken{Bytes: blindedMsg})
	if err != nil {
		t.Fatalf("BlindSign: %v", err)
	}
	if len(bsig.BlindedSig) != KeyBits/8 {
		t.Fatalf("blinded sig length = %d, want %d", len(bsig.BlindedSig), KeyBits/8)
	}

	usig, err := bsig.Unblind(secret, token)
	if err != nil {
		t.Fatalf("Unblind: %v", err)
	}
	if err := pk.BlindVerify(token, usig); err != nil {
		t.Fatalf("BlindVerify: %v", err)
	}
}

// TestMizaruBlindSignAndVerify exercises the full Mizaru-mode round trip with
// a small Merkle tree (4 subkeys), including Merkle membership verification.
func TestMizaruBlindSignAndVerify(t *testing.T) {
	const n = 4
	sk := GenerateSecretKeyN("test_mizaru", n)
	pk := sk.ToPublicKey()

	for epoch := uint16(0); epoch < n; epoch++ {
		token := RandomToken()
		subPub, err := sk.GetSubkeyPublicKey(epoch)
		if err != nil {
			t.Fatalf("epoch %d GetSubkeyPublicKey: %v", epoch, err)
		}
		subPubDER, err := publicKeyToPKCS1DER(subPub)
		if err != nil {
			t.Fatalf("epoch %d pkcs1 encode: %v", epoch, err)
		}
		blindedMsg, secret, err := rsaBlind(nil, subPub, token[:])
		if err != nil {
			t.Fatalf("epoch %d rsaBlind: %v", epoch, err)
		}
		bsig, err := sk.BlindSign(epoch, &BlindedClientToken{Bytes: blindedMsg})
		if err != nil {
			t.Fatalf("epoch %d BlindSign: %v", epoch, err)
		}
		usig, err := bsig.Unblind(secret, token)
		if err != nil {
			t.Fatalf("epoch %d Unblind: %v", epoch, err)
		}
		if err := pk.BlindVerify(token, usig); err != nil {
			t.Fatalf("epoch %d BlindVerify: %v", epoch, err)
		}
		// The used_key in the signature must match the subkey we blinded
		// against.
		if !bytes.Equal(usig.UsedKey, subPubDER) {
			t.Fatalf("epoch %d used_key mismatch", epoch)
		}
	}
}

// TestVerifyMember checks the Merkle membership proof directly: a correct
// branch verifies, a tampered branch fails, and a wrong root fails.
func TestVerifyMember(t *testing.T) {
	const n = 8
	sk := GenerateSecretKeyN("test_verify_member", n)
	pk := sk.ToPublicKey()

	for epoch := uint16(0); epoch < n; epoch++ {
		subPub, err := sk.GetSubkeyPublicKey(epoch)
		if err != nil {
			t.Fatalf("epoch %d GetSubkeyPublicKey: %v", epoch, err)
		}
		subDER, err := publicKeyToPKCS1DER(subPub)
		if err != nil {
			t.Fatalf("epoch %d pkcs1 encode: %v", epoch, err)
		}
		branch := sk.MerkleBranch(epoch)

		// Correct proof must verify.
		if err := VerifyMember(epoch, subDER, branch, pk.Root); err != nil {
			t.Fatalf("epoch %d VerifyMember (correct): %v", epoch, err)
		}

		// Tampered branch must fail.
		bad := make([]Hash, len(branch))
		copy(bad, branch)
		bad[0][0] ^= 0xff
		if err := VerifyMember(epoch, subDER, bad, pk.Root); err == nil {
			t.Fatalf("epoch %d VerifyMember (tampered branch) succeeded; want error", epoch)
		}

		// Wrong root must fail.
		var wrongRoot Hash
		wrongRoot[0] = pk.Root[0] ^ 0xff
		if err := VerifyMember(epoch, subDER, branch, wrongRoot); err == nil {
			t.Fatalf("epoch %d VerifyMember (wrong root) succeeded; want error", epoch)
		}

		// Wrong subkey must fail.
		otherEpoch := uint16((epoch + 1) % n)
		otherPub, _ := sk.GetSubkeyPublicKey(otherEpoch)
		otherDER, _ := publicKeyToPKCS1DER(otherPub)
		if err := VerifyMember(epoch, otherDER, branch, pk.Root); err == nil {
			t.Fatalf("epoch %d VerifyMember (wrong subkey) succeeded; want error", epoch)
		}
	}
}

// TestStdcodeRoundTrip ensures BlindedSignature and UnblindedSignature
// survive STDCODE marshal/unmarshal unchanged.
func TestStdcodeRoundTrip(t *testing.T) {
	const n = 4
	sk := GenerateSecretKeyN("test_stdcode", n)
	pk := sk.ToPublicKey()
	epoch := uint16(2)
	token := RandomToken()
	subPub, err := sk.GetSubkeyPublicKey(epoch)
	if err != nil {
		t.Fatalf("GetSubkeyPublicKey: %v", err)
	}
	blindedMsg, secret, err := rsaBlind(nil, subPub, token[:])
	if err != nil {
		t.Fatalf("rsaBlind: %v", err)
	}
	bsig, err := sk.BlindSign(epoch, &BlindedClientToken{Bytes: blindedMsg})
	if err != nil {
		t.Fatalf("BlindSign: %v", err)
	}
	usig, err := bsig.Unblind(secret, token)
	if err != nil {
		t.Fatalf("Unblind: %v", err)
	}

	// BlindedSignature round trip.
	enc, err := bsig.MarshalStdcode()
	if err != nil {
		t.Fatalf("BlindedSignature.MarshalStdcode: %v", err)
	}
	var bsig2 BlindedSignature
	if err := bsig2.UnmarshalStdcode(enc); err != nil {
		t.Fatalf("BlindedSignature.UnmarshalStdcode: %v", err)
	}
	if bsig2.Epoch != bsig.Epoch ||
		!bytes.Equal(bsig2.UsedKey, bsig.UsedKey) ||
		!hashesEqual(bsig2.MerkleBranch, bsig.MerkleBranch) ||
		!bytes.Equal(bsig2.BlindedSig, bsig.BlindedSig) {
		t.Fatalf("BlindedSignature round trip mismatch")
	}

	// UnblindedSignature round trip.
	encU, err := usig.MarshalStdcode()
	if err != nil {
		t.Fatalf("UnblindedSignature.MarshalStdcode: %v", err)
	}
	var usig2 UnblindedSignature
	if err := usig2.UnmarshalStdcode(encU); err != nil {
		t.Fatalf("UnblindedSignature.UnmarshalStdcode: %v", err)
	}
	if usig2.Epoch != usig.Epoch ||
		!bytes.Equal(usig2.UsedKey, usig.UsedKey) ||
		!hashesEqual(usig2.MerkleBranch, usig.MerkleBranch) ||
		!bytes.Equal(usig2.UnblindedSig, usig.UnblindedSig) {
		t.Fatalf("UnblindedSignature round trip mismatch")
	}

	// The deserialized unblinded signature must still verify.
	if err := pk.BlindVerify(token, &usig2); err != nil {
		t.Fatalf("BlindVerify after stdcode round trip: %v", err)
	}

	// Single-key stdcode round trip.
	sk1 := GenerateSingleSecretKey("test_stdcode_single")
	pk1, _ := sk1.ToPublicKey()
	rsaPub1, _ := pk1.Inner()
	tok := RandomToken()
	bm, sec, err := rsaBlind(nil, rsaPub1, tok[:])
	if err != nil {
		t.Fatalf("single rsaBlind: %v", err)
	}
	sb, err := sk1.BlindSign(&BlindedClientToken{Bytes: bm})
	if err != nil {
		t.Fatalf("single BlindSign: %v", err)
	}
	senc, err := sb.MarshalStdcode()
	if err != nil {
		t.Fatalf("SingleBlindedSignature.MarshalStdcode: %v", err)
	}
	var sb2 SingleBlindedSignature
	if err := sb2.UnmarshalStdcode(senc); err != nil {
		t.Fatalf("SingleBlindedSignature.UnmarshalStdcode: %v", err)
	}
	if !bytes.Equal(sb2.UsedKey, sb.UsedKey) || !bytes.Equal(sb2.BlindedSig, sb.BlindedSig) {
		t.Fatalf("SingleBlindedSignature round trip mismatch")
	}
	su, err := sb2.Unblind(sec, tok)
	if err != nil {
		t.Fatalf("single Unblind: %v", err)
	}
	uenc, err := su.MarshalStdcode()
	if err != nil {
		t.Fatalf("SingleUnblindedSignature.MarshalStdcode: %v", err)
	}
	var su2 SingleUnblindedSignature
	if err := su2.UnmarshalStdcode(uenc); err != nil {
		t.Fatalf("SingleUnblindedSignature.UnmarshalStdcode: %v", err)
	}
	if !bytes.Equal(su2.UnblindedSig, su.UnblindedSig) {
		t.Fatalf("SingleUnblindedSignature round trip mismatch")
	}
	if err := pk1.BlindVerify(tok, &su2); err != nil {
		t.Fatalf("single BlindVerify after round trip: %v", err)
	}
}

// TestCurrentEpoch sanity-checks the epoch helpers.
func TestCurrentEpoch(t *testing.T) {
	e := CurrentEpoch()
	if UnixToEpoch(0) != 0 {
		t.Fatalf("UnixToEpoch(0) = %d, want 0", UnixToEpoch(0))
	}
	if UnixToEpoch(86400) != 1 {
		t.Fatalf("UnixToEpoch(86400) = %d, want 1", UnixToEpoch(86400))
	}
	if UnixToEpoch(86400*1000) != 1000%65536 {
		t.Fatalf("UnixToEpoch(86400*1000) = %d", UnixToEpoch(86400*1000))
	}
	// CurrentEpoch must equal UnixToEpoch(now).
	now := uint64(time.Now().Unix())
	if e != UnixToEpoch(now) {
		t.Fatalf("CurrentEpoch %d != UnixToEpoch(now) %d", e, UnixToEpoch(now))
	}
}

func hashesEqual(a, b []Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
