package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/rolledback/pwsafe-service/backend/internal/config"
)

func newTestService(t *testing.T) (*AuthService, string, string) {
	t.Helper()
	dataDir := t.TempDir()
	configDir := t.TempDir()
	// Create empty settings.json
	os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)

	settings := &config.Settings{}
	svc := NewAuthService(dataDir, configDir, settings)
	return svc, dataDir, configDir
}

func TestGetMode_Unset(t *testing.T) {
	svc, _, _ := newTestService(t)
	if mode := svc.GetMode(); mode != "unset" {
		t.Errorf("expected 'unset', got %q", mode)
	}
}

func TestSetup_Disabled(t *testing.T) {
	svc, _, _ := newTestService(t)
	if err := svc.Setup("disabled", ""); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	if mode := svc.GetMode(); mode != "disabled" {
		t.Errorf("expected 'disabled', got %q", mode)
	}
}

func TestSetup_Enabled(t *testing.T) {
	svc, dataDir, _ := newTestService(t)
	if err := svc.Setup("enabled", "mypassword"); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	if mode := svc.GetMode(); mode != "enabled" {
		t.Errorf("expected 'enabled', got %q", mode)
	}
	// Verify hash file exists
	hashPath := filepath.Join(dataDir, ".password_hash")
	info, err := os.Stat(hashPath)
	if err != nil {
		t.Fatalf("hash file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Error("hash file is empty")
	}
}

func TestSetup_BlockedAfterModeSet(t *testing.T) {
	svc, _, _ := newTestService(t)
	if err := svc.Setup("disabled", ""); err != nil {
		t.Fatalf("first Setup failed: %v", err)
	}
	err := svc.Setup("enabled", "password")
	if err == nil {
		t.Fatal("expected error on second Setup, got nil")
	}
	if err.Error() != "auth mode already configured" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSetup_InvalidMode(t *testing.T) {
	svc, _, _ := newTestService(t)
	if err := svc.Setup("bogus", ""); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestSetup_EnabledNoPassword(t *testing.T) {
	svc, _, _ := newTestService(t)
	if err := svc.Setup("enabled", ""); err == nil {
		t.Fatal("expected error for enabled auth mode without password")
	}
}

func TestLogin_Success(t *testing.T) {
	svc, _, _ := newTestService(t)
	if err := svc.Setup("enabled", "testpass"); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	sessionID, err := svc.Login("testpass", "127.0.0.1")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if sessionID == "" {
		t.Error("expected non-empty session ID")
	}
	if !svc.ValidateSession(sessionID, "127.0.0.1") {
		t.Error("session should be valid after login")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	svc, _, _ := newTestService(t)
	if err := svc.Setup("enabled", "testpass"); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	_, err := svc.Login("wrongpass", "127.0.0.1")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestSession_Validation(t *testing.T) {
	svc, _, _ := newTestService(t)
	svc.Setup("enabled", "pass")

	sessionID, _ := svc.Login("pass", "127.0.0.1")

	if !svc.ValidateSession(sessionID, "127.0.0.1") {
		t.Error("session should be valid")
	}
	if !svc.IsAuthenticated(sessionID, "127.0.0.1") {
		t.Error("should be authenticated")
	}
	if svc.ValidateSession("bogus-session-id", "127.0.0.1") {
		t.Error("bogus session should not be valid")
	}
}

func TestSession_Expiry(t *testing.T) {
	dataDir := t.TempDir()
	configDir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)

	settings := &config.Settings{
		Auth: &config.AuthConfig{SessionTimeout: "100ms"},
	}
	svc := NewAuthService(dataDir, configDir, settings)
	svc.Setup("enabled", "pass")

	sessionID, _ := svc.Login("pass", "127.0.0.1")
	if !svc.ValidateSession(sessionID, "127.0.0.1") {
		t.Fatal("session should be valid immediately")
	}

	time.Sleep(200 * time.Millisecond)
	if svc.ValidateSession(sessionID, "127.0.0.1") {
		t.Error("session should be expired")
	}
}

func TestSession_InvalidationOnNewLogin(t *testing.T) {
	svc, _, _ := newTestService(t)
	svc.Setup("enabled", "pass")

	session1, _ := svc.Login("pass", "10.0.0.1")
	session2, _ := svc.Login("pass", "10.0.0.1")

	if svc.ValidateSession(session1, "10.0.0.1") {
		t.Error("first session should be invalidated after new login from same IP")
	}
	if !svc.ValidateSession(session2, "10.0.0.1") {
		t.Error("new session should be valid")
	}
}

func TestSession_MaxCap(t *testing.T) {
	svc, _, _ := newTestService(t)
	svc.Setup("enabled", "pass")

	// Create defaultMaxSessions sessions from different IPs, track the oldest
	var oldestSessionID string
	for i := 0; i < defaultMaxSessions; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		sid, err := svc.Login("pass", ip)
		if err != nil {
			t.Fatalf("Login %d failed: %v", i, err)
		}
		if i == 0 {
			oldestSessionID = sid
		}
	}

	if svc.SessionCount() != defaultMaxSessions {
		t.Errorf("expected %d sessions, got %d", defaultMaxSessions, svc.SessionCount())
	}

	// One more login should still succeed (evicts oldest)
	sessionID, err := svc.Login("pass", "172.16.0.1")
	if err != nil {
		t.Fatalf("Login should succeed: %v", err)
	}
	if !svc.ValidateSession(sessionID, "172.16.0.1") {
		t.Error("new session should be valid")
	}
	if svc.ValidateSession(oldestSessionID, "10.0.0.0") {
		t.Error("oldest session should have been evicted")
	}
	if svc.SessionCount() != defaultMaxSessions {
		t.Errorf("expected %d sessions after cap, got %d", defaultMaxSessions, svc.SessionCount())
	}
}

func TestLogout(t *testing.T) {
	svc, _, _ := newTestService(t)
	svc.Setup("enabled", "pass")

	sessionID, _ := svc.Login("pass", "127.0.0.1")
	svc.Logout(sessionID)

	if svc.ValidateSession(sessionID, "127.0.0.1") {
		t.Error("session should be invalid after logout")
	}
}

func TestPasswordHashFile_Permissions(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" {
		t.Skip("file permissions not reliable on Windows")
	}
	svc, dataDir, _ := newTestService(t)
	svc.Setup("enabled", "pass")

	hashPath := filepath.Join(dataDir, ".password_hash")
	info, err := os.Stat(hashPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected permissions 0600, got %04o", perm)
	}
}

func TestCookieHelpers(t *testing.T) {
	// Test SetSessionCookie
	w := httptest.NewRecorder()
	timeout := 3 * time.Minute
	SetSessionCookie(w, "test-session-id", false, timeout)
	resp := w.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != sessionCookieName {
		t.Errorf("expected cookie name %q, got %q", sessionCookieName, c.Name)
	}
	if c.Value != "test-session-id" {
		t.Errorf("expected value 'test-session-id', got %q", c.Value)
	}
	if !c.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if c.Path != "/" {
		t.Errorf("expected path '/', got %q", c.Path)
	}
	if c.MaxAge != int(timeout.Seconds()) {
		t.Errorf("expected MaxAge %d, got %d", int(timeout.Seconds()), c.MaxAge)
	}

	// Test ClearSessionCookie
	w2 := httptest.NewRecorder()
	ClearSessionCookie(w2)
	resp2 := w2.Result()
	cookies2 := resp2.Cookies()
	if len(cookies2) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies2))
	}
	if cookies2[0].MaxAge != -1 {
		t.Errorf("expected MaxAge -1, got %d", cookies2[0].MaxAge)
	}

	// Test GetSessionIDFromRequest with valid session
	req := httptest.NewRequest("GET", "/", nil)
	// Create a valid 32-char hex session ID
	validSessionID := "0123456789abcdef0123456789abcdef"
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: validSessionID})
	if got := GetSessionIDFromRequest(req); got != validSessionID {
		t.Errorf("expected %q, got %q", validSessionID, got)
	}

	// Test GetSessionIDFromRequest with invalid format (not hex)
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "not-a-valid-hex-string-!!!!"})
	if got := GetSessionIDFromRequest(req2); got != "" {
		t.Errorf("expected empty string for invalid hex, got %q", got)
	}

	// Test GetSessionIDFromRequest with wrong length
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "abc123"})
	if got := GetSessionIDFromRequest(req3); got != "" {
		t.Errorf("expected empty string for wrong length, got %q", got)
	}

	// No cookie
	req4 := httptest.NewRequest("GET", "/", nil)
	if got := GetSessionIDFromRequest(req4); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestCleanupExpiredSessions(t *testing.T) {
	dataDir := t.TempDir()
	configDir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)

	settings := &config.Settings{
		Auth: &config.AuthConfig{SessionTimeout: "50ms"},
	}
	svc := NewAuthService(dataDir, configDir, settings)
	svc.Setup("enabled", "pass")

	sessionID, _ := svc.Login("pass", "127.0.0.1")
	if !svc.ValidateSession(sessionID, "127.0.0.1") {
		t.Fatal("session should be valid")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// ValidateSession deletes expired sessions as a side effect
	if svc.ValidateSession(sessionID, "127.0.0.1") {
		t.Error("session should be expired")
	}

	if svc.SessionCount() != 0 {
		t.Errorf("expected 0 sessions after cleanup, got %d", svc.SessionCount())
	}
}

func TestSession_AbsoluteLifetime(t *testing.T) {
	dataDir := t.TempDir()
	configDir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)

	settings := &config.Settings{
		Auth: &config.AuthConfig{SessionTimeout: "10s"},
	}
	svc := NewAuthService(dataDir, configDir, settings)
	svc.Setup("enabled", "pass")

	sessionID, err := svc.Login("pass", "127.0.0.1")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if !svc.ValidateSession(sessionID, "127.0.0.1") {
		t.Fatal("session should be valid immediately")
	}

	// Manually set CreatedAt to exceed defaultMaxAbsoluteLifetime (30m)
	svc.mu.Lock()
	svc.sessions[sessionID].CreatedAt = time.Now().Add(-31 * time.Minute)
	svc.mu.Unlock()

	if svc.ValidateSession(sessionID, "127.0.0.1") {
		t.Error("session should be invalid after exceeding absolute lifetime")
	}
}

func TestValidateSession_ExtendsExpiry(t *testing.T) {
	svc, _, _ := newTestService(t)
	svc.Setup("enabled", "pass")

	sessionID, _ := svc.Login("pass", "127.0.0.1")

	svc.mu.Lock()
	expiryBefore := svc.sessions[sessionID].ExpiresAt
	svc.mu.Unlock()

	time.Sleep(10 * time.Millisecond)

	// ValidateSession should extend ExpiresAt
	svc.ValidateSession(sessionID, "127.0.0.1")

	svc.mu.Lock()
	expiryAfterValidate := svc.sessions[sessionID].ExpiresAt
	svc.mu.Unlock()

	if !expiryAfterValidate.After(expiryBefore) {
		t.Error("ValidateSession should extend ExpiresAt")
	}

	time.Sleep(10 * time.Millisecond)

	// IsAuthenticated should NOT extend ExpiresAt
	svc.IsAuthenticated(sessionID, "127.0.0.1")

	svc.mu.Lock()
	expiryAfterIsAuth := svc.sessions[sessionID].ExpiresAt
	svc.mu.Unlock()

	if !expiryAfterIsAuth.Equal(expiryAfterValidate) {
		t.Error("IsAuthenticated should NOT extend ExpiresAt")
	}
}

func TestSession_IPMismatch(t *testing.T) {
	svc, _, _ := newTestService(t)
	svc.Setup("enabled", "pass")

	sessionID, _ := svc.Login("pass", "10.0.0.1")

	// Same IP should work
	if !svc.ValidateSession(sessionID, "10.0.0.1") {
		t.Error("session should be valid from same IP")
	}

	// Different IP should fail
	if svc.ValidateSession(sessionID, "10.0.0.2") {
		t.Error("session should be rejected from different IP")
	}

	// IsAuthenticated should also reject different IP
	if svc.IsAuthenticated(sessionID, "10.0.0.2") {
		t.Error("IsAuthenticated should reject different IP")
	}

	// Original IP should still work (session not deleted by IP mismatch)
	if !svc.IsAuthenticated(sessionID, "10.0.0.1") {
		t.Error("session should still be valid from original IP")
	}
}

func TestLogin_MissingHashFile(t *testing.T) {
	svc, _, _ := newTestService(t)

	// Set mode to "enabled" manually without creating hash file
	svc.mu.Lock()
	if svc.settings.Auth == nil {
		svc.settings.Auth = &config.AuthConfig{}
	}
	svc.settings.Auth.Mode = "enabled"
	svc.mu.Unlock()

	_, err := svc.Login("pass", "127.0.0.1")
	if err == nil {
		t.Fatal("expected error when hash file is missing")
	}
	if err.Error() != "invalid credentials" {
		t.Errorf("expected 'invalid credentials', got %q", err.Error())
	}
}

func TestNewAuthService_InvalidTimeout(t *testing.T) {
	dataDir := t.TempDir()
	configDir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)

	settings := &config.Settings{
		Auth: &config.AuthConfig{SessionTimeout: "bogus"},
	}
	svc := NewAuthService(dataDir, configDir, settings)

	if svc.GetSessionTimeout() != defaultSessionTimeout {
		t.Errorf("expected default timeout %v, got %v", defaultSessionTimeout, svc.GetSessionTimeout())
	}
}

func TestNewAuthService_InvalidBcryptCost(t *testing.T) {
	tests := []struct {
		name string
		cost int
	}{
		{"too low", 2},
		{"too high", 40},
		{"negative", -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			configDir := t.TempDir()
			os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)

			settings := &config.Settings{
				Auth: &config.AuthConfig{BcryptCost: tc.cost},
			}
			svc := NewAuthService(dataDir, configDir, settings)

			if svc.GetBcryptCost() != defaultBcryptCost {
				t.Errorf("expected default bcrypt cost %d for invalid value %d, got %d", defaultBcryptCost, tc.cost, svc.GetBcryptCost())
			}
		})
	}
}

func TestNewAuthService_InvalidMaxSessions(t *testing.T) {
	tests := []struct {
		name string
		val  int
	}{
		{"negative", -1},
		{"too high", 20000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			configDir := t.TempDir()
			os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)

			settings := &config.Settings{
				Auth: &config.AuthConfig{MaxSessions: tc.val},
			}
			svc := NewAuthService(dataDir, configDir, settings)

			if svc.GetMaxSessions() != defaultMaxSessions {
				t.Errorf("expected default max sessions %d for invalid value %d, got %d", defaultMaxSessions, tc.val, svc.GetMaxSessions())
			}
		})
	}
}

func TestNewAuthService_InvalidMaxSessionLifetime(t *testing.T) {
	tests := []struct {
		name string
		val  string
	}{
		{"unparseable", "bogus"},
		{"too short", "30s"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			configDir := t.TempDir()
			os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)

			settings := &config.Settings{
				Auth: &config.AuthConfig{MaxSessionLifetime: tc.val},
			}
			svc := NewAuthService(dataDir, configDir, settings)

			if svc.GetMaxAbsoluteLifetime() != defaultMaxAbsoluteLifetime {
				t.Errorf("expected default max absolute lifetime %s for invalid value %q, got %s", defaultMaxAbsoluteLifetime, tc.val, svc.GetMaxAbsoluteLifetime())
			}
		})
	}
}

func TestSession_MaxCapCustom(t *testing.T) {
	dataDir := t.TempDir()
	configDir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)

	settings := &config.Settings{
		Auth: &config.AuthConfig{MaxSessions: 2},
	}
	svc := NewAuthService(dataDir, configDir, settings)
	svc.Setup("enabled", "pass")

	// Create 2 sessions from different IPs
	sid1, _ := svc.Login("pass", "10.0.0.1")
	svc.Login("pass", "10.0.0.2")

	if svc.SessionCount() != 2 {
		t.Errorf("expected 2 sessions, got %d", svc.SessionCount())
	}

	// Third login should evict oldest
	svc.Login("pass", "10.0.0.3")
	if svc.SessionCount() != 2 {
		t.Errorf("expected 2 sessions after eviction, got %d", svc.SessionCount())
	}
	if svc.ValidateSession(sid1, "10.0.0.1") {
		t.Error("oldest session should have been evicted")
	}
}

func TestSession_CustomAbsoluteLifetime(t *testing.T) {
	dataDir := t.TempDir()
	configDir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)

	settings := &config.Settings{
		Auth: &config.AuthConfig{
			SessionTimeout:     "10s",
			MaxSessionLifetime: "1m",
		},
	}
	svc := NewAuthService(dataDir, configDir, settings)
	svc.Setup("enabled", "pass")

	sessionID, _ := svc.Login("pass", "127.0.0.1")
	if !svc.ValidateSession(sessionID, "127.0.0.1") {
		t.Fatal("session should be valid immediately")
	}

	// Manually set CreatedAt to exceed the configured 1m lifetime
	svc.mu.Lock()
	svc.sessions[sessionID].CreatedAt = time.Now().Add(-61 * time.Second)
	svc.mu.Unlock()

	if svc.ValidateSession(sessionID, "127.0.0.1") {
		t.Error("session should be expired by absolute lifetime")
	}
}

func TestNewAuthService_BcryptCostUsedInSetup(t *testing.T) {
	dataDir := t.TempDir()
	configDir := t.TempDir()
	os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644)

	settings := &config.Settings{
		Auth: &config.AuthConfig{BcryptCost: 4},
	}
	svc := NewAuthService(dataDir, configDir, settings)

	if err := svc.Setup("enabled", "testpass"); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Verify the hash was generated with the configured cost
	hashPath := filepath.Join(dataDir, ".password_hash")
	hash, err := os.ReadFile(hashPath)
	if err != nil {
		t.Fatalf("failed to read hash file: %v", err)
	}
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		t.Fatalf("failed to get bcrypt cost: %v", err)
	}
	if cost != 4 {
		t.Errorf("expected bcrypt cost 4, got %d", cost)
	}

	// Login should still work with the lower cost hash
	_, err = svc.Login("testpass", "127.0.0.1")
	if err != nil {
		t.Fatalf("Login failed with custom bcrypt cost: %v", err)
	}
}
