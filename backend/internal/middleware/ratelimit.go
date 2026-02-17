package middleware

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/rolledback/pwsafe-service/backend/internal/config"
	"golang.org/x/time/rate"
)

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type RateLimiter struct {
	visitors       map[string]*visitor
	mu             sync.Mutex
	rate           rate.Limit
	burst          int
	trustedProxies []string
}

// RateLimiters holds all rate limiter tiers.
type RateLimiters struct {
	Standard *RateLimiter
	Strict   *RateLimiter
	Web      *RateLimiter
}

var rateLimitDefaults = map[string]struct {
	rate  rate.Limit
	burst int
}{
	"standard": {5, 5},
	"strict":   {0.2, 2},
	"web":      {50, 50},
}

// resolveTier returns the rate and burst for a named tier,
// using config values if valid or defaults otherwise.
func resolveTier(cfg *config.RateLimiterConfig, tier string) (rate.Limit, int) {
	defaults := rateLimitDefaults[tier]

	if cfg == nil {
		return defaults.rate, defaults.burst
	}

	var tierCfg *config.RateLimitTierConfig
	switch tier {
	case "standard":
		tierCfg = cfg.Standard
	case "strict":
		tierCfg = cfg.Strict
	case "web":
		tierCfg = cfg.Web
	}

	if tierCfg == nil {
		return defaults.rate, defaults.burst
	}

	if tierCfg.Rate > 0 && tierCfg.Burst >= 1 {
		return rate.Limit(tierCfg.Rate), tierCfg.Burst
	}

	log.Printf("Warning: invalid %s rate limiter config (rate must be >0, burst must be >=1), using defaults", tier)
	return defaults.rate, defaults.burst
}

// NewRateLimiters creates all rate limiter tiers from config, using defaults for any unconfigured tier.
func NewRateLimiters(ctx context.Context, cfg *config.RateLimiterConfig, trustedProxies []string) *RateLimiters {
	stdRate, stdBurst := resolveTier(cfg, "standard")
	strictRate, strictBurst := resolveTier(cfg, "strict")
	webRate, webBurst := resolveTier(cfg, "web")

	log.Printf("Rate limiters: standard=%.2f/s burst=%d, strict=%.2f/s burst=%d, web=%.2f/s burst=%d",
		float64(stdRate), stdBurst, float64(strictRate), strictBurst, float64(webRate), webBurst)

	return &RateLimiters{
		Standard: NewRateLimiter(ctx, stdRate, stdBurst, trustedProxies),
		Strict:   NewRateLimiter(ctx, strictRate, strictBurst, trustedProxies),
		Web:      NewRateLimiter(ctx, webRate, webBurst, trustedProxies),
	}
}

func NewRateLimiter(ctx context.Context, r rate.Limit, b int, trustedProxies []string) *RateLimiter {
	rl := &RateLimiter{
		visitors:       make(map[string]*visitor),
		rate:           r,
		burst:          b,
		trustedProxies: trustedProxies,
	}
	go rl.cleanup(ctx)
	return rl
}

// maxVisitors is the hard cap on the visitor map size to prevent memory exhaustion.
const maxVisitors = 10_000

// denyLimiter is a pre-allocated limiter that always denies requests.
var denyLimiter = rate.NewLimiter(0, 0)

func (rl *RateLimiter) getVisitor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		if len(rl.visitors) >= maxVisitors {
			return denyLimiter
		}
		v = &visitor{
			limiter:  rate.NewLimiter(rl.rate, rl.burst),
			lastSeen: time.Now(),
		}
		rl.visitors[ip] = v
		return v.limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

func (rl *RateLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			for ip, v := range rl.visitors {
				if time.Since(v.lastSeen) > 10*time.Minute {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

func (rl *RateLimiter) Limit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := GetClientIP(r, rl.trustedProxies)

		limiter := rl.getVisitor(ip)
		if !limiter.Allow() {
			log.Printf("Rate limit exceeded: ip=%s path=%s method=%s", ip, r.URL.Path, r.Method)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}
