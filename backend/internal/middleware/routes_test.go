package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/time/rate"
)

func okHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func TestRegisterRoutes_CORSApplied(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, []Route{
		{Pattern: "/api/test", Handler: okHandler},
	}, "csrf-token", newTestAuthService(t), nil)

	req := httptest.NewRequest("OPTIONS", "/api/test", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for OPTIONS, got %d", rec.Code)
	}
	if rec.Body.String() == "OK" {
		t.Error("handler should not be called for OPTIONS (CORS should short-circuit)")
	}
}

func TestRegisterRoutes_CsrfEnforced(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, []Route{
		{Pattern: "/api/test", Handler: okHandler, Csrf: true},
	}, "csrf-token", newTestAuthService(t), nil)

	// Without token → 403
	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 without CSRF token, got %d", rec.Code)
	}

	// With token → handler reached
	req = httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-PWSAFE-CSRF-Token", "csrf-token")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Body.String() != "OK" {
		t.Errorf("expected handler reached with valid CSRF token, got %q", rec.Body.String())
	}
}

func TestRegisterRoutes_CsrfSkipped(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, []Route{
		{Pattern: "/api/test", Handler: okHandler, Csrf: false},
	}, "csrf-token", newTestAuthService(t), nil)

	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Body.String() != "OK" {
		t.Errorf("expected handler reached without CSRF when Csrf=false, got %q", rec.Body.String())
	}
}

func TestRegisterRoutes_MethodEnforced(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, []Route{
		{Pattern: "/api/test", Handler: okHandler, Method: http.MethodPost},
	}, "csrf-token", newTestAuthService(t), nil)

	// Wrong method → 405
	req := httptest.NewRequest("GET", "/api/test", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET on POST-only route, got %d", rec.Code)
	}

	// Correct method → handler reached
	req = httptest.NewRequest("POST", "/api/test", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Body.String() != "OK" {
		t.Errorf("expected handler reached with POST, got %q", rec.Body.String())
	}
}

func TestRegisterRoutes_MethodEmpty_AllowsAny(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, []Route{
		{Pattern: "/api/test", Handler: okHandler},
	}, "csrf-token", newTestAuthService(t), nil)

	for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
		req := httptest.NewRequest(method, "/api/test", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Body.String() != "OK" {
			t.Errorf("expected handler reached for %s when Method is empty, got %q", method, rec.Body.String())
		}
	}
}

func TestRegisterRoutes_MethodOptionsAlwaysAllowed(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, []Route{
		{Pattern: "/api/test", Handler: okHandler, Method: http.MethodPost},
	}, "csrf-token", newTestAuthService(t), nil)

	// OPTIONS should pass through method check (handled by CORS)
	req := httptest.NewRequest("OPTIONS", "/api/test", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for OPTIONS even on POST-only route, got %d", rec.Code)
	}
}

func TestRegisterRoutes_AuthEnforced(t *testing.T) {
	svc := newTestAuthService(t)
	svc.Setup("enabled", "pass")

	mux := http.NewServeMux()
	RegisterRoutes(mux, []Route{
		{Pattern: "/api/test", Handler: okHandler, Auth: true},
	}, "csrf-token", svc, nil)

	// No session → 401
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without session, got %d", rec.Code)
	}
}

func TestRegisterRoutes_RateLimiterApplied(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl := NewRateLimiter(ctx, rate.Limit(0.01), 1, nil)

	mux := http.NewServeMux()
	RegisterRoutes(mux, []Route{
		{Pattern: "/api/test", Handler: okHandler, Limiter: rl},
	}, "csrf-token", newTestAuthService(t), nil)

	// First request → OK (uses burst)
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Body.String() != "OK" {
		t.Errorf("expected first request to pass, got %q", rec.Body.String())
	}

	// Second request → 429 (burst exhausted)
	req = httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after burst exhausted, got %d", rec.Code)
	}
}
