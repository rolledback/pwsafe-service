package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rolledback/pwsafe-service/backend/internal/auth"
	"github.com/rolledback/pwsafe-service/backend/internal/config"
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

// --- RequireCsrfToken tests ---

func TestRequireCsrfToken_ValidToken(t *testing.T) {
	handler := RequireCsrfToken("test-csrf-token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/safes", nil)
	req.Header.Set("X-PWSAFE-CSRF-Token", "test-csrf-token")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireCsrfToken_MissingToken(t *testing.T) {
	handler := RequireCsrfToken("test-csrf-token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/safes", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestRequireCsrfToken_WrongToken(t *testing.T) {
	handler := RequireCsrfToken("test-csrf-token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/safes", nil)
	req.Header.Set("X-PWSAFE-CSRF-Token", "wrong-csrf-token")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestRequireCsrfToken_OptionsSkipped(t *testing.T) {
	called := false
	handler := RequireCsrfToken("test-csrf-token", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("OPTIONS", "/api/safes", nil)
	req.Header.Set("X-PWSAFE-CSRF-Token", "wrong-csrf-token")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if !called {
		t.Error("expected next handler to be called for OPTIONS")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireCsrfToken_CallbackSkipped(t *testing.T) {
	called := false
	handler := RequireCsrfToken("test-csrf-token", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/providers/mock/auth/callback", nil)
	req.Header.Set("X-PWSAFE-CSRF-Token", "wrong-csrf-token")
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
	handler := SecurityHeaders(false, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	handler := SecurityHeaders(false, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	rl := NewRateLimiter(ctx, rate.Limit(1), burst, nil)
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
	rl := NewRateLimiter(ctx, rate.Limit(0.01), burst, nil)
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

	rl := NewRateLimiter(ctx, rate.Limit(10), 10, nil)
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

// --- RequireAuth tests ---

func newTestAuthService(t *testing.T) *auth.AuthService {
	t.Helper()
	dataDir := t.TempDir()
	configDir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)
	return auth.NewAuthService(dataDir, configDir, &config.Settings{})
}

func TestRequireAuth_Unset_Returns503(t *testing.T) {
	svc := newTestAuthService(t)
	handler := RequireAuth(svc, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/safes", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestRequireAuth_Disabled_Passthrough(t *testing.T) {
	svc := newTestAuthService(t)
	svc.Setup("disabled", "")
	called := false
	handler := RequireAuth(svc, nil, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/safes", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler(rec, req)
	if !called {
		t.Error("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireAuth_Enabled_ValidSession(t *testing.T) {
	svc := newTestAuthService(t)
	svc.Setup("enabled", "pass")
	sessionID, err := svc.Login("pass", "127.0.0.1")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	called := false
	handler := RequireAuth(svc, nil, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/safes", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(&http.Cookie{Name: "pwsafe_session_id", Value: sessionID})
	rec := httptest.NewRecorder()
	handler(rec, req)
	if !called {
		t.Error("expected next handler to be called for valid session")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireAuth_Enabled_NoSession(t *testing.T) {
	svc := newTestAuthService(t)
	svc.Setup("enabled", "pass")
	handler := RequireAuth(svc, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/safes", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestRequireAuth_Enabled_ExpiredSession(t *testing.T) {
	dataDir := t.TempDir()
	configDir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)
	settings := &config.Settings{Auth: &config.AuthConfig{SessionTimeout: "50ms"}}
	svc := auth.NewAuthService(dataDir, configDir, settings)
	svc.Setup("enabled", "pass")
	sessionID, err := svc.Login("pass", "127.0.0.1")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	handler := RequireAuth(svc, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/api/safes", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(&http.Cookie{Name: "pwsafe_session_id", Value: sessionID})
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestRequireAuth_OPTIONS_Bypass(t *testing.T) {
	svc := newTestAuthService(t)
	svc.Setup("enabled", "pass")
	handler := RequireAuth(svc, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Prove auth IS enforced: GET without session → 401
	getReq := httptest.NewRequest("GET", "/api/safes", nil)
	getReq.RemoteAddr = "127.0.0.1:12345"
	getRec := httptest.NewRecorder()
	handler(getRec, getReq)
	if getRec.Code != http.StatusUnauthorized {
		t.Errorf("GET without session should be 401, got %d", getRec.Code)
	}

	// Prove OPTIONS bypasses auth: same conditions → 200
	optReq := httptest.NewRequest("OPTIONS", "/api/safes", nil)
	optReq.RemoteAddr = "127.0.0.1:12345"
	optRec := httptest.NewRecorder()
	handler(optRec, optReq)
	if optRec.Code != http.StatusOK {
		t.Errorf("OPTIONS should bypass auth and return 200, got %d", optRec.Code)
	}
}

// --- GetClientIP tests ---

func TestGetClientIP_WithPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	if ip := GetClientIP(req, nil); ip != "192.168.1.1" {
		t.Errorf("expected '192.168.1.1', got %q", ip)
	}
}

func TestGetClientIP_WithoutPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1"
	if ip := GetClientIP(req, nil); ip != "192.168.1.1" {
		t.Errorf("expected '192.168.1.1', got %q", ip)
	}
}

func TestGetClientIP_IPv6WithPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:1234"
	if ip := GetClientIP(req, nil); ip != "::1" {
		t.Errorf("expected '::1', got %q", ip)
	}
}

func TestGetClientIP_IPv6WithoutPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "::1"
	if ip := GetClientIP(req, nil); ip != "::1" {
		t.Errorf("expected '::1', got %q", ip)
	}
}

func TestGetClientIP_Empty(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ""
	if ip := GetClientIP(req, nil); ip != "" {
		t.Errorf("expected empty string, got %q", ip)
	}
}

func TestGetClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Real-IP", "203.0.113.50")
	// Trusted proxy: honours X-Real-IP
	if ip := GetClientIP(req, []string{"10.0.0.1"}); ip != "203.0.113.50" {
		t.Errorf("expected '203.0.113.50', got %q", ip)
	}
}

func TestGetClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.1")
	// Trusted proxy: honours X-Forwarded-For
	if ip := GetClientIP(req, []string{"10.0.0.1"}); ip != "203.0.113.50" {
		t.Errorf("expected '203.0.113.50', got %q", ip)
	}
}

func TestGetClientIP_XRealIP_TakesPrecedence(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Real-IP", "1.2.3.4")
	req.Header.Set("X-Forwarded-For", "5.6.7.8")
	// Trusted proxy: X-Real-IP takes precedence over X-Forwarded-For
	if ip := GetClientIP(req, []string{"10.0.0.1"}); ip != "1.2.3.4" {
		t.Errorf("expected X-Real-IP '1.2.3.4', got %q", ip)
	}
}

func TestGetClientIP_NoHeaders_FallsBack(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:5678"
	if ip := GetClientIP(req, nil); ip != "192.168.1.1" {
		t.Errorf("expected '192.168.1.1', got %q", ip)
	}
}
