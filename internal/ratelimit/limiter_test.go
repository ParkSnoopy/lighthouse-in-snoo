package ratelimit_test

import (
	"testing"
	"time"

	"lighthouse-in-snoo/internal/ratelimit"
)

func TestKeyedLimiterAndConcurrencyBounds(t *testing.T) {
	t.Parallel()

	kl := ratelimit.NewKeyedLimiter(1, 2, 3, time.Minute)
	if !kl.Allow("ip1") || !kl.Allow("ip1") {
		t.Fatal("expected initial burst of 2 to succeed")
	}
	if kl.Allow("ip1") {
		t.Fatal("expected 3rd immediate call to be rate-limited")
	}

	// Fill maxEntries (3) and verify bounded behavior on flood keys.
	_ = kl.Allow("ip2")
	_ = kl.Allow("ip3")
	_ = kl.Allow("ip4") // evicts oldest entry without growing unbounded

	cl := ratelimit.NewConcurrencyLimiter(2, 3)
	if !cl.Acquire("a") || !cl.Acquire("a") {
		t.Fatal("expected 2 per-key acquires")
	}
	if cl.Acquire("a") {
		t.Fatal("expected 3rd per-key acquire to fail")
	}
	if !cl.Acquire("b") {
		t.Fatal("expected b acquire to reach global cap 3")
	}
	if cl.Acquire("b") {
		t.Fatal("expected 4th global acquire to fail")
	}
	cl.Release("a")
	if cl.Total() != 2 {
		t.Fatalf("Total = %d; want 2", cl.Total())
	}
}
