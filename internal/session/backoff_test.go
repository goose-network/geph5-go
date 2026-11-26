package session

import (
	"testing"
	"time"
)

// TestBackoffScaleNoOverflow is a regression test for the sessionWorker
// backoff shift: failures is unbounded, and the old
// time.Duration(1 << uint(failures)) wrapped negative at failures=63 and to
// 0 at failures>=64 (the 30-60s timeout product already wrapped negative from
// failures=28), collapsing the dial timeout and retry wait to <= 0 and
// spinning all six workers at 100% CPU. The clamped scale must stay positive
// and keep the worker's capped products inside (0,120s] / [0,120s].
func TestBackoffScaleNoOverflow(t *testing.T) {
	for failures := 0; failures <= 1000; failures++ {
		scale := backoffScale(failures)
		if scale <= 0 {
			t.Fatalf("failures=%d: scale=%d, want > 0", failures, scale)
		}
		if failures <= maxBackoffExponent && scale != time.Duration(1<<uint(failures)) {
			t.Fatalf("failures=%d: scale=%d, want bit-identical 1<<failures", failures, scale)
		}
		timeout := 60 * time.Second * scale
		if timeout <= 0 {
			t.Fatalf("failures=%d: timeout product wrapped: %v", failures, timeout)
		}
		if timeout > 120*time.Second {
			timeout = 120 * time.Second
		}
		wait := 99 * time.Millisecond * scale
		if wait < 0 {
			t.Fatalf("failures=%d: wait product wrapped: %v", failures, wait)
		}
		if wait > 120*time.Second {
			wait = 120 * time.Second
		}
		if timeout <= 0 || timeout > 120*time.Second || wait < 0 || wait > 120*time.Second {
			t.Fatalf("failures=%d: timeout=%v wait=%v out of bounds", failures, timeout, wait)
		}
	}
}
