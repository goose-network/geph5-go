package melpow

import (
	"encoding/base64"
	"testing"
)

// TestGenerateVerify checks that a generated proof verifies against the same
// puzzle/difficulty and fails for a wrong puzzle or difficulty. This catches
// structural port errors (node encoding, accumulator framing, DAG labeling).
func TestGenerateVerify(t *testing.T) {
	for _, difficulty := range []int{4, 8, 12} {
		puzzle := []byte("geph5-go melpow self-test")
		proof := Generate(puzzle, difficulty, nil)
		if !proof.Verify(puzzle, difficulty) {
			t.Fatalf("difficulty %d: generated proof does not verify", difficulty)
		}
		if proof.Verify([]byte("wrong puzzle"), difficulty) {
			t.Fatalf("difficulty %d: proof verified against wrong puzzle", difficulty)
		}
		if proof.Verify(puzzle, difficulty+1) {
			t.Fatalf("difficulty %d: proof verified against wrong difficulty", difficulty)
		}
	}
}

// TestRoundTrip checks ToBytes/FromBytes preserve the proof.
func TestRoundTrip(t *testing.T) {
	puzzle := []byte("round trip")
	proof := Generate(puzzle, 10, nil)
	bts := proof.ToBytes()
	if len(bts)%40 != 0 {
		t.Fatalf("proof bytes not a multiple of 40: %d", len(bts))
	}
	back, ok := FromBytes(bts)
	if !ok {
		t.Fatal("FromBytes failed")
	}
	if !back.Verify(puzzle, 10) {
		t.Fatal("round-tripped proof does not verify")
	}
}

// TestSolveVerify checks the base64 solution string round-trips through
// VerifySolution (the broker-side check).
func TestSolveVerify(t *testing.T) {
	puzzle := "solution-string-test"
	sol := SolvePuzzle(puzzle, 10, nil)
	if _, err := base64.RawStdEncoding.DecodeString(sol); err != nil {
		t.Fatalf("solution is not base64-no-pad: %v", err)
	}
	if !VerifySolution(puzzle, 10, sol) {
		t.Fatal("VerifySolution rejected a freshly solved puzzle")
	}
	if VerifySolution("other", 10, sol) {
		t.Fatal("VerifySolution accepted a wrong puzzle")
	}
}

// TestEmptyPuzzle mirrors melpow's own test_simple (empty puzzle, difficulty 16).
func TestEmptyPuzzle(t *testing.T) {
	proof := Generate([]byte{}, 16, nil)
	if !proof.Verify([]byte{}, 16) {
		t.Fatal("empty-puzzle proof does not verify")
	}
	if proof.Verify([]byte("hello"), 16) {
		t.Fatal("empty-puzzle proof verified against 'hello'")
	}
}

func BenchmarkGenerate24(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Generate([]byte("bench puzzle"), 24, nil)
	}
}
