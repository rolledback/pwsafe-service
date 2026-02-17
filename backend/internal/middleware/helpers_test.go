package middleware

import (
	"net/http/httptest"
	"testing"
)

// --- GetClientIP trusted proxy tests ---

func TestGetClientIP_IgnoresProxyHeaders_WhenNotTrusted(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	req.Header.Set("X-Real-IP", "10.10.10.10")
	req.Header.Set("X-Forwarded-For", "10.20.30.40")

	ip := GetClientIP(req, nil)
	if ip != "192.168.1.1" {
		t.Errorf("expected remote IP '192.168.1.1', got %q", ip)
	}
}

func TestGetClientIP_IgnoresProxyHeaders_WhenTrustedListDoesNotMatch(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:9999"
	req.Header.Set("X-Real-IP", "10.10.10.10")

	ip := GetClientIP(req, []string{"172.16.0.1"})
	if ip != "192.168.1.1" {
		t.Errorf("expected remote IP '192.168.1.1', got %q", ip)
	}
}

func TestGetClientIP_StripsPort_WhenNotTrusted(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	req.Header.Set("X-Real-IP", "spoofed")

	ip := GetClientIP(req, nil)
	if ip != "203.0.113.5" {
		t.Errorf("expected '203.0.113.5', got %q", ip)
	}
}

func TestGetClientIP_HonorsXRealIP_WhenTrusted(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Real-IP", "203.0.113.50")

	ip := GetClientIP(req, []string{"10.0.0.1"})
	if ip != "203.0.113.50" {
		t.Errorf("expected '203.0.113.50', got %q", ip)
	}
}

func TestGetClientIP_HonorsXForwardedFor_WhenTrusted(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 10.0.0.1")

	ip := GetClientIP(req, []string{"10.0.0.1"})
	if ip != "198.51.100.1" {
		t.Errorf("expected '198.51.100.1', got %q", ip)
	}
}

func TestGetClientIP_XFF_RightmostNonTrusted(t *testing.T) {
	// Multi-hop: "spoofed, real-client, proxy" with proxy in trusted list
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "spoofed, 203.0.113.50, 10.0.0.2")

	ip := GetClientIP(req, []string{"10.0.0.1", "10.0.0.2"})
	if ip != "203.0.113.50" {
		t.Errorf("expected '203.0.113.50', got %q", ip)
	}
}

func TestGetClientIP_XFF_AllTrusted_FallsBack(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.2, 10.0.0.3")

	ip := GetClientIP(req, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"})
	if ip != "10.0.0.1" {
		t.Errorf("expected fallback to '10.0.0.1', got %q", ip)
	}
}

func TestGetClientIP_FallsBackToRemoteIP_WhenTrustedButNoHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"

	ip := GetClientIP(req, []string{"10.0.0.1"})
	if ip != "10.0.0.1" {
		t.Errorf("expected '10.0.0.1', got %q", ip)
	}
}

func TestGetClientIP_BareIP_NoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1"
	req.Header.Set("X-Real-IP", "spoofed")

	ip := GetClientIP(req, nil)
	if ip != "192.168.1.1" {
		t.Errorf("expected '192.168.1.1', got %q", ip)
	}
}

// --- IsTrustedProxy tests ---

func TestIsTrustedProxy_EmptyList(t *testing.T) {
	if IsTrustedProxy("10.0.0.1", nil) {
		t.Error("expected false for nil list")
	}
	if IsTrustedProxy("10.0.0.1", []string{}) {
		t.Error("expected false for empty list")
	}
}

func TestIsTrustedProxy_Match(t *testing.T) {
	if !IsTrustedProxy("10.0.0.1", []string{"10.0.0.1", "10.0.0.2"}) {
		t.Error("expected true for matching IP")
	}
}

func TestIsTrustedProxy_NoMatch(t *testing.T) {
	if IsTrustedProxy("10.0.0.3", []string{"10.0.0.1", "10.0.0.2"}) {
		t.Error("expected false for non-matching IP")
	}
}
