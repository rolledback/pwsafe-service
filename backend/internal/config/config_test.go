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
