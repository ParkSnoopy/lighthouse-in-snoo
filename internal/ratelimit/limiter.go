package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type bucketEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// KeyedLimiter enforces token-bucket rate limits per key with a strict upper bound
// on tracked keys to prevent memory exhaustion during flood attacks.
type KeyedLimiter struct {
	mu         sync.Mutex
	r          rate.Limit
	burst      int
	maxEntries int
	ttl        time.Duration
	entries    map[string]*bucketEntry
	nowFunc    func() time.Time
}

// NewKeyedLimiter creates a bounded per-key token-bucket rate limiter.
func NewKeyedLimiter(rps float64, burst, maxEntries int, ttl time.Duration) *KeyedLimiter {
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	if burst <= 0 {
		burst = 1
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &KeyedLimiter{
		r:          rate.Limit(rps),
		burst:      burst,
		maxEntries: maxEntries,
		ttl:        ttl,
		entries:    make(map[string]*bucketEntry),
		nowFunc:    time.Now,
	}
}

// Allow reports whether an event for key may happen now.
func (kl *KeyedLimiter) Allow(key string) bool {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	now := kl.nowFunc()
	if entry, ok := kl.entries[key]; ok {
		entry.lastSeen = now
		return entry.limiter.AllowN(now, 1)
	}

	if len(kl.entries) >= kl.maxEntries {
		kl.evictLocked(now)
		if len(kl.entries) >= kl.maxEntries {
			// Table full of active flood sources: fail closed without allocating.
			return false
		}
	}

	lim := rate.NewLimiter(kl.r, kl.burst)
	kl.entries[key] = &bucketEntry{
		limiter:  lim,
		lastSeen: now,
	}
	return lim.AllowN(now, 1)
}

func (kl *KeyedLimiter) evictLocked(now time.Time) {
	var oldestKey string
	var oldestTime time.Time
	for k, v := range kl.entries {
		if now.Sub(v.lastSeen) > kl.ttl {
			delete(kl.entries, k)
			continue
		}
		if oldestKey == "" || v.lastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.lastSeen
		}
	}
	if len(kl.entries) >= kl.maxEntries && oldestKey != "" {
		delete(kl.entries, oldestKey)
	}
}

// ConcurrencyLimiter bounds active concurrent sessions/connections per key and globally.
type ConcurrencyLimiter struct {
	mu        sync.Mutex
	maxPerKey int
	maxTotal  int
	total     int
	counts    map[string]int
}

// NewConcurrencyLimiter creates a bounded concurrency tracker.
func NewConcurrencyLimiter(maxPerKey, maxTotal int) *ConcurrencyLimiter {
	return &ConcurrencyLimiter{
		maxPerKey: maxPerKey,
		maxTotal:  maxTotal,
		counts:    make(map[string]int),
	}
}

// Acquire increments the active count for key if within per-key and global bounds.
func (cl *ConcurrencyLimiter) Acquire(key string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.maxTotal > 0 && cl.total >= cl.maxTotal {
		return false
	}
	cur := cl.counts[key]
	if cl.maxPerKey > 0 && cur >= cl.maxPerKey {
		return false
	}
	cl.counts[key] = cur + 1
	cl.total++
	return true
}

// Release decrements the active count for key.
func (cl *ConcurrencyLimiter) Release(key string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	cur, ok := cl.counts[key]
	if !ok || cur <= 0 {
		return
	}
	if cur == 1 {
		delete(cl.counts, key)
	} else {
		cl.counts[key] = cur - 1
	}
	if cl.total > 0 {
		cl.total--
	}
}

// Total returns the current total active count.
func (cl *ConcurrencyLimiter) Total() int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.total
}
