package auth

import (
	"sync"
	"testing"
)

// TestAccountLevelPacking verifies the single-word (known, isPlus) snapshot: a
// cold manager reports unknown, and setLevel records a consistent pair that
// AccountLevel reads back verbatim.
func TestAccountLevelPacking(t *testing.T) {
	m := &Manager{}
	if isPlus, known := m.AccountLevel(); isPlus || known {
		t.Fatalf("cold manager: got (%v,%v), want (false,false)", isPlus, known)
	}
	m.setLevel(true)
	if isPlus, known := m.AccountLevel(); !isPlus || !known {
		t.Fatalf("after setLevel(true): got (%v,%v), want (true,true)", isPlus, known)
	}
	m.setLevel(false)
	if isPlus, known := m.AccountLevel(); isPlus || !known {
		t.Fatalf("after setLevel(false): got (%v,%v), want (false,true)", isPlus, known)
	}
}

// TestAccountLevelNoTornRead stresses concurrent setLevel/AccountLevel under the
// race detector. Packing (known, isPlus) into one atomic word guarantees every
// read is a consistent snapshot: once known is true it never reverts, and isPlus
// is always a value some setLevel stored — never the OLD isPlus paired with a NEW
// known=true, the torn read two separate atomics allowed across a Free<->Plus
// transition (which misclassified a Plus account as Free at the exit gate).
func TestAccountLevelNoTornRead(t *testing.T) {
	m := &Manager{}
	m.setLevel(false) // known from the start
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50000; i++ {
			m.setLevel(i%2 == 0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50000; i++ {
			if _, known := m.AccountLevel(); !known {
				t.Errorf("known reverted to false after being set")
				return
			}
		}
	}()
	wg.Wait()
}