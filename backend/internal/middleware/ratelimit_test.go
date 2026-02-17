package middleware

import (
	"context"
	"fmt"
	"testing"

	"golang.org/x/time/rate"
)

func TestRateLimiter_MapCap_RejectsAtCapacity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl := NewRateLimiter(ctx, rate.Limit(100), 100, nil)

	// Fill the visitor map to capacity
	for i := 0; i < maxVisitors; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		limiter := rl.getVisitor(ip)
		if limiter == denyLimiter {
			t.Fatalf("visitor %d should have been admitted, but got deny limiter", i)
		}
	}

	if len(rl.visitors) != maxVisitors {
		t.Fatalf("expected %d visitors, got %d", maxVisitors, len(rl.visitors))
	}

	// The next new IP should get the deny limiter
	limiter := rl.getVisitor("99.99.99.99")
	if limiter != denyLimiter {
		t.Error("expected deny limiter when at capacity, but got a normal limiter")
	}

	// Deny limiter should reject
	if limiter.Allow() {
		t.Error("deny limiter should not allow requests")
	}

	// Existing visitors should still work
	limiter = rl.getVisitor("10.0.0.0")
	if limiter == denyLimiter {
		t.Error("existing visitor should not get deny limiter")
	}
}
