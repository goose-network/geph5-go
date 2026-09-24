package mizaru2

import (
	"encoding/json"
	"fmt"
)

// jsonBlindedSignature is the serde_json shape of Rust's BlindedSignature:
//
//	{ "epoch": u16, "used_key": [u8...], "merkle_branch": [[u8;32]...],
//	  "blinded_sig": [u8...] }
//
// serde serializes Vec<u8> as an array of integers and blake3::Hash (a
// [u8;32] newtype) via serialize_bytes as an array of 32 integers. We model
// both as []byte on the Go side, but encoding/json marshals []byte as a
// base64 STRING by default, which is NOT what serde produces. We therefore
// use a temporary struct of json.RawMessage fields and decode each byte
// array with decodeJSONArray below (matching the array-of-ints wire format).
type jsonBlindedSignature struct {
	Epoch        uint16            `json:"epoch"`
	UsedKey      json.RawMessage   `json:"used_key"`
	MerkleBranch json.RawMessage   `json:"merkle_branch"`
	BlindedSig   json.RawMessage   `json:"blinded_sig"`
}

// MarshalJSON encodes a BlindedSignature as serde_json would: byte vectors
// and hashes as JSON arrays of integers.
func (b BlindedSignature) MarshalJSON() ([]byte, error) {
	branch := make([]json.RawMessage, len(b.MerkleBranch))
	for i, h := range b.MerkleBranch {
		branch[i] = encodeByteArray(h[:])
	}
	tmp := struct {
		Epoch        uint16          `json:"epoch"`
		UsedKey      json.RawMessage `json:"used_key"`
		MerkleBranch json.RawMessage `json:"merkle_branch"`
		BlindedSig   json.RawMessage `json:"blinded_sig"`
	}{
		Epoch:        b.Epoch,
		UsedKey:      encodeByteArray(b.UsedKey),
		MerkleBranch: mustJSONArray(branch),
		BlindedSig:   encodeByteArray(b.BlindedSig),
	}
	return json.Marshal(tmp)
}

// UnmarshalJSON decodes a BlindedSignature from its serde_json form.
func (b *BlindedSignature) UnmarshalJSON(data []byte) error {
	var tmp jsonBlindedSignature
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	usedKey, err := decodeByteArray(tmp.UsedKey)
	if err != nil {
		return fmt.Errorf("mizaru2: decode used_key: %w", err)
	}
	blindedSig, err := decodeByteArray(tmp.BlindedSig)
	if err != nil {
		return fmt.Errorf("mizaru2: decode blinded_sig: %w", err)
	}
	branch, err := decodeHashArray(tmp.MerkleBranch)
	if err != nil {
		return fmt.Errorf("mizaru2: decode merkle_branch: %w", err)
	}
	b.Epoch = tmp.Epoch
	b.UsedKey = usedKey
	b.MerkleBranch = branch
	b.BlindedSig = blindedSig
	return nil
}

// MarshalJSON encodes an UnblindedSignature as serde_json would.
func (u UnblindedSignature) MarshalJSON() ([]byte, error) {
	branch := make([]json.RawMessage, len(u.MerkleBranch))
	for i, h := range u.MerkleBranch {
		branch[i] = encodeByteArray(h[:])
	}
	tmp := struct {
		Epoch        uint16          `json:"epoch"`
		UsedKey      json.RawMessage `json:"used_key"`
		MerkleBranch json.RawMessage `json:"merkle_branch"`
		UnblindedSig json.RawMessage `json:"unblinded_sig"`
	}{
		Epoch:        u.Epoch,
		UsedKey:      encodeByteArray(u.UsedKey),
		MerkleBranch: mustJSONArray(branch),
		UnblindedSig: encodeByteArray(u.UnblindedSig),
	}
	return json.Marshal(tmp)
}

// UnmarshalJSON decodes an UnblindedSignature from its serde_json form.
func (u *UnblindedSignature) UnmarshalJSON(data []byte) error {
	var tmp struct {
		Epoch        uint16          `json:"epoch"`
		UsedKey      json.RawMessage `json:"used_key"`
		MerkleBranch json.RawMessage `json:"merkle_branch"`
		UnblindedSig json.RawMessage `json:"unblinded_sig"`
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	usedKey, err := decodeByteArray(tmp.UsedKey)
	if err != nil {
		return fmt.Errorf("mizaru2: decode used_key: %w", err)
	}
	unblindedSig, err := decodeByteArray(tmp.UnblindedSig)
	if err != nil {
		return fmt.Errorf("mizaru2: decode unblinded_sig: %w", err)
	}
	branch, err := decodeHashArray(tmp.MerkleBranch)
	if err != nil {
		return fmt.Errorf("mizaru2: decode merkle_branch: %w", err)
	}
	u.Epoch = tmp.Epoch
	u.UsedKey = usedKey
	u.MerkleBranch = branch
	u.UnblindedSig = unblindedSig
	return nil
}

// MarshalJSON encodes a SingleBlindedSignature as serde_json would: the
// used_key and blinded_sig Vec<u8> fields as JSON arrays of integers (0..255).
// Rust derives Serialize for SingleBlindedSignature with default serde (NOT
// serde_bytes), which serializes Vec<u8> as a sequence of numbers.
func (b SingleBlindedSignature) MarshalJSON() ([]byte, error) {
	tmp := struct {
		UsedKey    json.RawMessage `json:"used_key"`
		BlindedSig json.RawMessage `json:"blinded_sig"`
	}{
		UsedKey:    encodeByteArray(b.UsedKey),
		BlindedSig: encodeByteArray(b.BlindedSig),
	}
	return json.Marshal(tmp)
}

// UnmarshalJSON decodes a SingleBlindedSignature from its serde_json form.
func (b *SingleBlindedSignature) UnmarshalJSON(data []byte) error {
	var tmp struct {
		UsedKey    json.RawMessage `json:"used_key"`
		BlindedSig json.RawMessage `json:"blinded_sig"`
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	usedKey, err := decodeByteArray(tmp.UsedKey)
	if err != nil {
		return fmt.Errorf("mizaru2: decode used_key: %w", err)
	}
	blindedSig, err := decodeByteArray(tmp.BlindedSig)
	if err != nil {
		return fmt.Errorf("mizaru2: decode blinded_sig: %w", err)
	}
	b.UsedKey = usedKey
	b.BlindedSig = blindedSig
	return nil
}

// MarshalJSON encodes a SingleUnblindedSignature as serde_json would: the
// unblinded_sig Vec<u8> field as a JSON array of integers (0..255).
func (u SingleUnblindedSignature) MarshalJSON() ([]byte, error) {
	tmp := struct {
		UnblindedSig json.RawMessage `json:"unblinded_sig"`
	}{
		UnblindedSig: encodeByteArray(u.UnblindedSig),
	}
	return json.Marshal(tmp)
}

// UnmarshalJSON decodes a SingleUnblindedSignature from its serde_json form.
func (u *SingleUnblindedSignature) UnmarshalJSON(data []byte) error {
	var tmp struct {
		UnblindedSig json.RawMessage `json:"unblinded_sig"`
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	unblindedSig, err := decodeByteArray(tmp.UnblindedSig)
	if err != nil {
		return fmt.Errorf("mizaru2: decode unblinded_sig: %w", err)
	}
	u.UnblindedSig = unblindedSig
	return nil
}

// MarshalJSON encodes a ClientToken ([u8; 32]) as serde_json would: a JSON
// array of 32 integers (0..255). Rust derives Serialize for ClientToken with
// default serde, which serializes [u8; N] as a sequence of numbers.
func (t ClientToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(encodeByteArray(t[:]))
}

// UnmarshalJSON decodes a ClientToken from its serde_json form (a JSON array
// of 32 integers).
func (t *ClientToken) UnmarshalJSON(data []byte) error {
	b, err := decodeByteArray(data)
	if err != nil {
		return fmt.Errorf("mizaru2: decode client token: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("mizaru2: client token: expected 32 bytes, got %d", len(b))
	}
	copy(t[:], b)
	return nil
}

// encodeByteArray encodes a byte slice as a JSON array of integers (0..255),
// matching serde's serialize_bytes for Vec<u8> / [u8; N].
func encodeByteArray(b []byte) json.RawMessage {
	arr := make([]uint16, len(b))
	for i, v := range b {
		arr[i] = uint16(v)
	}
	out, err := json.Marshal(arr)
	if err != nil {
		return json.RawMessage("null")
	}
	return out
}

// decodeByteArray decodes a JSON array of integers (or a base64 string as a
// fallback) into a byte slice, matching serde's serialize_bytes output.
func decodeByteArray(v json.RawMessage) ([]byte, error) {
	if len(v) == 0 || string(v) == "null" {
		return nil, nil
	}
	// serde_bytes -> array of integers.
	var arr []uint8
	if err := json.Unmarshal(v, &arr); err == nil {
		return arr, nil
	}
	// Some serializers emit a base64 string; accept it as a fallback.
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("expected byte array, got %s", string(v))
}

// decodeHashArray decodes a JSON array of 32-byte arrays into []Hash.
func decodeHashArray(v json.RawMessage) ([]Hash, error) {
	if len(v) == 0 || string(v) == "null" {
		return nil, nil
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(v, &raws); err != nil {
		return nil, err
	}
	out := make([]Hash, len(raws))
	for i, r := range raws {
		b, err := decodeByteArray(r)
		if err != nil {
			return nil, err
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("hash %d: expected 32 bytes, got %d", i, len(b))
		}
		copy(out[i][:], b)
	}
	return out, nil
}

// mustJSONArray marshals a slice of json.RawMessage into a JSON array.
func mustJSONArray(elems []json.RawMessage) json.RawMessage {
	out, err := json.Marshal(elems)
	if err != nil {
		return json.RawMessage("null")
	}
	return out
}
