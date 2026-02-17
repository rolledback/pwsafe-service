package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders_ErrorResponsesCarryHeaders(t *testing.T) {
	handler := SecurityHeaders(false, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}))

	for _, code := range []int{http.StatusForbidden, http.StatusNotFound} {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, http.StatusText(code), code)
		})
		h := SecurityHeaders(false, nil, inner)
		req := httptest.NewRequest("GET", "/api/test", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("status %d: expected X-Content-Type-Options nosniff", code)
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("status %d: expected X-Frame-Options DENY", code)
		}
	}
	_ = handler // suppress unused
}

func TestSecurityHeaders_CacheControlOnAPI(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := SecurityHeaders(false, nil, inner)

	// /api/ path should have Cache-Control: no-store
	req := httptest.NewRequest("GET", "/api/safes", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("expected Cache-Control: no-store on /api/ path")
	}

	// /web/ path should NOT have Cache-Control: no-store
	req = httptest.NewRequest("GET", "/web/index.html", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("Cache-Control") == "no-store" {
		t.Error("unexpected Cache-Control: no-store on /web/ path")
	}
}

func TestSecurityHeaders_HSTS(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name           string
		hstsEnabled    bool
		tls            bool
		trustedProxies []string
		remoteAddr     string
		xfp            string // X-Forwarded-Proto
		expectHSTS     bool
	}{
		{"enabled+TLS", true, true, nil, "", "", true},
		{"enabled+noTLS", true, false, nil, "", "", false},
		{"disabled+TLS", false, true, nil, "", "", false},
		{"disabled+noTLS", false, false, nil, "", "", false},
		{"enabled+proxy+https", true, false, []string{"10.0.0.1"}, "10.0.0.1:1234", "https", true},
		{"enabled+proxy+http", true, false, []string{"10.0.0.1"}, "10.0.0.1:1234", "http", false},
		{"enabled+untrusted+https", true, false, nil, "10.0.0.1:1234", "https", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := SecurityHeaders(tc.hstsEnabled, tc.trustedProxies, inner)
			req := httptest.NewRequest("GET", "/", nil)
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tc.remoteAddr != "" {
				req.RemoteAddr = tc.remoteAddr
			}
			if tc.xfp != "" {
				req.Header.Set("X-Forwarded-Proto", tc.xfp)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			hsts := rec.Header().Get("Strict-Transport-Security")
			if tc.expectHSTS && hsts == "" {
				t.Error("expected HSTS header but not found")
			}
			if !tc.expectHSTS && hsts != "" {
				t.Errorf("unexpected HSTS header: %s", hsts)
			}
		})
	}
}
