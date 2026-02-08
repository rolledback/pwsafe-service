package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// --- IsOAuthCallback tests ---

func TestIsOAuthCallback_ValidPath(t *testing.T) {
	if !IsOAuthCallback("/api/providers/mock/auth/callback") {
		t.Error("expected true for valid OAuth callback path")
	}
}

func TestIsOAuthCallback_NoProviderPrefix(t *testing.T) {
	if IsOAuthCallback("/auth/callback") {
		t.Error("expected false for path without /api/providers/ prefix")
	}
}

func TestIsOAuthCallback_ApiButNotProvider(t *testing.T) {
	if IsOAuthCallback("/api/safes/auth/callback") {
		t.Error("expected false for /api/safes/ path")
	}
}

func TestIsOAuthCallback_EmptyPath(t *testing.T) {
	if IsOAuthCallback("") {
		t.Error("expected false for empty path")
	}
}

// --- RequireToken tests ---

func TestRequireToken_ValidToken(t *testing.T) {
	handler := RequireToken("test-token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/safes", nil)
	req.Header.Set("X-PWSAFE-Token", "test-token")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireToken_MissingToken(t *testing.T) {
	handler := RequireToken("test-token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/safes", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestRequireToken_WrongToken(t *testing.T) {
	handler := RequireToken("test-token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/safes", nil)
	req.Header.Set("X-PWSAFE-Token", "wrong-token")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestRequireToken_OptionsSkipped(t *testing.T) {
	called := false
	handler := RequireToken("test-token", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("OPTIONS", "/api/safes", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if !called {
		t.Error("expected next handler to be called for OPTIONS")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireToken_CallbackSkipped(t *testing.T) {
	called := false
	handler := RequireToken("test-token", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/providers/mock/auth/callback", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if !called {
		t.Error("expected next handler to be called for OAuth callback")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// --- CORS tests ---

func TestCORS_OptionsReturns200(t *testing.T) {
	handler := CORS(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for OPTIONS")
	})
	req := httptest.NewRequest("OPTIONS", "/api/safes", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestCORS_NonOptionsPassesThrough(t *testing.T) {
	called := false
	handler := CORS(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/safes", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if !called {
		t.Error("expected next handler to be called for GET")
	}
}

// --- SecurityHeaders tests ---

func TestSecurityHeaders_SetsHeaders(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	checks := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"Referrer-Policy":       "no-referrer",
	}
	for header, expected := range checks {
		if got := rec.Header().Get(header); got != expected {
			t.Errorf("header %s: expected %q, got %q", header, expected, got)
		}
	}
}

func TestSecurityHeaders_CallsNext(t *testing.T) {
	called := false
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called {
		t.Error("expected next handler to be called")
	}
}

// --- RateLimiter tests ---

func TestRateLimiter_AllowsBurst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	burst := 5
	rl := NewRateLimiter(ctx, rate.Limit(1), burst)
	handler := rl.Limit(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < burst; i++ {
		req := httptest.NewRequest("GET", "/api/safes", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i, rec.Code)
		}
	}
}

func TestRateLimiter_BlocksAfterBurst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	burst := 2
	rl := NewRateLimiter(ctx, rate.Limit(0.01), burst)
	handler := rl.Limit(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Exhaust burst
	for i := 0; i < burst; i++ {
		req := httptest.NewRequest("GET", "/api/safes", nil)
		req.RemoteAddr = "10.0.0.1:5678"
		rec := httptest.NewRecorder()
		handler(rec, req)
	}

	// Next request should be rate limited
	req := httptest.NewRequest("GET", "/api/safes", nil)
	req.RemoteAddr = "10.0.0.1:5678"
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec.Code)
	}
}

func TestRateLimiter_VisitorLastSeenUpdated(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl := NewRateLimiter(ctx, rate.Limit(10), 10)
	rl.getVisitor("1.2.3.4")
	time.Sleep(10 * time.Millisecond)
	rl.getVisitor("1.2.3.4")

	rl.mu.Lock()
	defer rl.mu.Unlock()
	v := rl.visitors["1.2.3.4"]
	if time.Since(v.lastSeen) > 5*time.Millisecond {
		t.Error("expected lastSeen to be updated on second getVisitor call")
	}
}

// --- Logging tests ---

func TestLogging_SkipsNonAPIPath(t *testing.T) {
	called := false
	handler := Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/web/foo", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called {
		t.Error("expected next handler to be called for non-API path")
	}
}

func TestLogging_RecordsStatusCode(t *testing.T) {
	handler := Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	req := httptest.NewRequest("POST", "/api/safes", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rec.Code)
	}
}
