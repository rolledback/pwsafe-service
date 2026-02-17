package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rolledback/pwsafe-service/backend/internal/auth"
	"github.com/rolledback/pwsafe-service/backend/internal/config"
)

func newTestAuthHandler(t *testing.T) *AuthHandler {
	t.Helper()
	dataDir := t.TempDir()
	configDir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)
	settings := &config.Settings{}
	svc := auth.NewAuthService(dataDir, configDir, settings)
	return NewAuthHandler(svc, nil)
}

func newEnabledAuthHandler(t *testing.T) *AuthHandler {
	t.Helper()
	dataDir := t.TempDir()
	configDir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)
	settings := &config.Settings{}
	svc := auth.NewAuthService(dataDir, configDir, settings)
	svc.Setup("enabled", "testpass")
	return NewAuthHandler(svc, nil)
}

func TestStatus_GET_ReturnsMode(t *testing.T) {
	h := newTestAuthHandler(t)

	// Unset mode
	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.Status(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["mode"] != "unset" {
		t.Errorf("expected mode 'unset', got %q", resp["mode"])
	}

	// After setup → disabled
	h.authService.Setup("disabled", "")
	req2 := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req2.RemoteAddr = "127.0.0.1:12345"
	w2 := httptest.NewRecorder()
	h.Status(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}
	var resp2 map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&resp2)
	if resp2["mode"] != "disabled" {
		t.Errorf("expected mode 'disabled', got %q", resp2["mode"])
	}
}

func TestSetup_POST_Disabled(t *testing.T) {
	h := newTestAuthHandler(t)
	body, _ := json.Marshal(map[string]string{"mode": "disabled"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.Setup(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestSetup_MalformedJSON(t *testing.T) {
	h := newTestAuthHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", bytes.NewReader([]byte("{invalid")))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.Setup(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSetup_AlreadyConfigured(t *testing.T) {
	h := newTestAuthHandler(t)

	// First setup
	body, _ := json.Marshal(map[string]string{"mode": "disabled"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.Setup(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first setup failed: %d", w.Code)
	}

	// Second setup → 403
	body2, _ := json.Marshal(map[string]string{"mode": "enabled", "password": "pass"})
	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/setup", bytes.NewReader(body2))
	req2.RemoteAddr = "127.0.0.1:12345"
	w2 := httptest.NewRecorder()
	h.Setup(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w2.Code)
	}
}

func TestLogin_Success_SetsCookie(t *testing.T) {
	h := newEnabledAuthHandler(t)
	body, _ := json.Marshal(map[string]string{"password": "testpass"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "pwsafe_session_id" && c.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Set-Cookie with pwsafe_session_id")
	}
}

func TestLogin_Failure_NoCookie(t *testing.T) {
	h := newEnabledAuthHandler(t)
	body, _ := json.Marshal(map[string]string{"password": "wrongpass"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}

	setCookie := w.Header().Get("Set-Cookie")
	if strings.Contains(setCookie, "pwsafe_session_id") {
		t.Error("should not set pwsafe_session_id cookie on failed login")
	}
}

func TestLogin_MalformedJSON(t *testing.T) {
	h := newEnabledAuthHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte("{bad")))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.Login(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestLogout_ClearsCookie(t *testing.T) {
	h := newEnabledAuthHandler(t)

	// Login first
	body, _ := json.Marshal(map[string]string{"password": "testpass"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d", w.Code)
	}

	// Extract session cookie
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "pwsafe_session_id" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie from login")
	}

	// Logout
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	logoutReq.RemoteAddr = "127.0.0.1:12345"
	logoutReq.AddCookie(sessionCookie)
	w2 := httptest.NewRecorder()
	h.Logout(w2, logoutReq)

	if w2.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w2.Code)
	}

	cookies := w2.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "pwsafe_session_id" && c.MaxAge < 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Set-Cookie with pwsafe_session_id and negative MaxAge on logout")
	}
}

func TestLogin_OversizedBody_Rejected(t *testing.T) {
	h := newEnabledAuthHandler(t)
	// Create a body larger than 1KB
	bigBody := strings.Repeat("x", 2048)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(bigBody)))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized body, got %d", w.Code)
	}
}

func TestSetup_OversizedBody_Rejected(t *testing.T) {
	h := newTestAuthHandler(t)
	bigBody := strings.Repeat("x", 2048)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", bytes.NewReader([]byte(bigBody)))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.Setup(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized body, got %d", w.Code)
	}
}
