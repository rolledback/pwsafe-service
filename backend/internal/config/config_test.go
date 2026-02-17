package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSettings_MissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	settings, err := LoadSettings(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if settings == nil {
		t.Fatal("expected non-nil settings")
	}
	if settings.BaseURL != "" {
		t.Errorf("expected empty BaseURL, got %q", settings.BaseURL)
	}
	if settings.Providers != nil {
		t.Errorf("expected nil Providers, got %v", settings.Providers)
	}
}

func TestLoadSettings_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), []byte{}, 0644); err != nil {
		t.Fatalf("failed to create empty file: %v", err)
	}
	settings, err := LoadSettings(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if settings == nil {
		t.Fatal("expected non-nil settings")
	}
	if settings.BaseURL != "" {
		t.Errorf("expected empty BaseURL, got %q", settings.BaseURL)
	}
	if settings.Providers != nil {
		t.Errorf("expected nil Providers, got %v", settings.Providers)
	}
}

func TestLoadSettings_ValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte(`{
		"baseUrl": "https://example.com",
		"providers": {
			"oidc": {
				"clientId": "my-client",
				"enabled": true
			}
		}
	}`)
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), data, 0644); err != nil {
		t.Fatalf("failed to write settings file: %v", err)
	}
	settings, err := LoadSettings(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if settings.BaseURL != "https://example.com" {
		t.Errorf("expected BaseURL %q, got %q", "https://example.com", settings.BaseURL)
	}
	if settings.Providers == nil {
		t.Fatal("expected non-nil Providers")
	}
	oidc, ok := settings.Providers["oidc"]
	if !ok {
		t.Fatal("expected 'oidc' provider")
	}
	if oidc["clientId"] != "my-client" {
		t.Errorf("expected clientId %q, got %v", "my-client", oidc["clientId"])
	}
	if oidc["enabled"] != true {
		t.Errorf("expected enabled true, got %v", oidc["enabled"])
	}
}

func TestLoadSettings_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte(`{not valid json}`)
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), data, 0644); err != nil {
		t.Fatalf("failed to write settings file: %v", err)
	}
	settings, err := LoadSettings(tmpDir)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if settings != nil {
		t.Errorf("expected nil settings on error, got %v", settings)
	}
}

func TestLoadSettings_WithSyncInterval(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte(`{"syncInterval": "30s", "providers": {}}`)
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), data, 0644); err != nil {
		t.Fatalf("failed to write settings file: %v", err)
	}
	settings, err := LoadSettings(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if settings.SyncInterval != "30s" {
		t.Errorf("expected SyncInterval %q, got %q", "30s", settings.SyncInterval)
	}
}

func TestLoadSettings_AuthConfig(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte(`{
		"auth": {
			"mode": "enabled",
			"sessionTimeout": "5m",
			"bcryptCost": 12,
			"maxSessions": 8,
			"maxSessionLifetime": "1h"
		}
	}`)
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), data, 0644); err != nil {
		t.Fatalf("failed to write settings file: %v", err)
	}
	settings, err := LoadSettings(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if settings.Auth == nil {
		t.Fatal("expected non-nil Auth")
	}
	if settings.Auth.Mode != "enabled" {
		t.Errorf("expected Mode %q, got %q", "enabled", settings.Auth.Mode)
	}
	if settings.Auth.SessionTimeout != "5m" {
		t.Errorf("expected SessionTimeout %q, got %q", "5m", settings.Auth.SessionTimeout)
	}
	if settings.Auth.BcryptCost != 12 {
		t.Errorf("expected BcryptCost 12, got %d", settings.Auth.BcryptCost)
	}
	if settings.Auth.MaxSessions != 8 {
		t.Errorf("expected MaxSessions 8, got %d", settings.Auth.MaxSessions)
	}
	if settings.Auth.MaxSessionLifetime != "1h" {
		t.Errorf("expected MaxSessionLifetime %q, got %q", "1h", settings.Auth.MaxSessionLifetime)
	}
}

func TestLoadSettings_RateLimiterConfig(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte(`{
		"rateLimiter": {
			"standard": {"rate": 10, "burst": 20},
			"strict": {"rate": 0.5, "burst": 3},
			"web": {"rate": 100, "burst": 200}
		}
	}`)
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), data, 0644); err != nil {
		t.Fatalf("failed to write settings file: %v", err)
	}
	settings, err := LoadSettings(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if settings.RateLimiter == nil {
		t.Fatal("expected non-nil RateLimiter")
	}
	if settings.RateLimiter.Standard == nil {
		t.Fatal("expected non-nil Standard")
	}
	if settings.RateLimiter.Standard.Rate != 10 {
		t.Errorf("expected Standard.Rate 10, got %f", settings.RateLimiter.Standard.Rate)
	}
	if settings.RateLimiter.Standard.Burst != 20 {
		t.Errorf("expected Standard.Burst 20, got %d", settings.RateLimiter.Standard.Burst)
	}
	if settings.RateLimiter.Strict == nil {
		t.Fatal("expected non-nil Strict")
	}
	if settings.RateLimiter.Strict.Rate != 0.5 {
		t.Errorf("expected Strict.Rate 0.5, got %f", settings.RateLimiter.Strict.Rate)
	}
	if settings.RateLimiter.Strict.Burst != 3 {
		t.Errorf("expected Strict.Burst 3, got %d", settings.RateLimiter.Strict.Burst)
	}
	if settings.RateLimiter.Web == nil {
		t.Fatal("expected non-nil Web")
	}
	if settings.RateLimiter.Web.Rate != 100 {
		t.Errorf("expected Web.Rate 100, got %f", settings.RateLimiter.Web.Rate)
	}
	if settings.RateLimiter.Web.Burst != 200 {
		t.Errorf("expected Web.Burst 200, got %d", settings.RateLimiter.Web.Burst)
	}
}

func TestLoadSettings_OmittedFieldsAreZero(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte(`{"auth": {"mode": "enabled"}}`)
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), data, 0644); err != nil {
		t.Fatalf("failed to write settings file: %v", err)
	}
	settings, err := LoadSettings(tmpDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if settings.Auth.BcryptCost != 0 {
		t.Errorf("expected BcryptCost 0 (omitted), got %d", settings.Auth.BcryptCost)
	}
	if settings.Auth.MaxSessions != 0 {
		t.Errorf("expected MaxSessions 0 (omitted), got %d", settings.Auth.MaxSessions)
	}
	if settings.Auth.MaxSessionLifetime != "" {
		t.Errorf("expected MaxSessionLifetime empty (omitted), got %q", settings.Auth.MaxSessionLifetime)
	}
	if settings.RateLimiter != nil {
		t.Errorf("expected nil RateLimiter (omitted), got %v", settings.RateLimiter)
	}
}

func TestLoadSettings_InvalidFieldType(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte(`{"auth": {"maxSessions": "notanumber"}}`)
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), data, 0644); err != nil {
		t.Fatalf("failed to write settings file: %v", err)
	}
	_, err := LoadSettings(tmpDir)
	if err == nil {
		t.Error("expected error for invalid type in JSON, got nil")
	}
}

func TestGetMaxSafeFileSize_Default(t *testing.T) {
	s := &Settings{}
	got := s.GetMaxSafeFileSize()
	expected := int64(10 << 20)
	if got != expected {
		t.Errorf("expected default %d, got %d", expected, got)
	}
}

func TestGetMaxSafeFileSize_CustomValue(t *testing.T) {
	s := &Settings{MaxSafeFileSize: 5 * 1024 * 1024}
	got := s.GetMaxSafeFileSize()
	if got != 5*1024*1024 {
		t.Errorf("expected %d, got %d", 5*1024*1024, got)
	}
}
