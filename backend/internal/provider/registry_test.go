package provider

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// mockFactory creates a simple mock provider for testing
func mockFactory(providerDir, baseURL string, settingsJSON []byte) (SyncableSafesProvider, error) {
	return &mockProvider{
		id:          filepath.Base(providerDir),
		displayName: "Mock " + filepath.Base(providerDir),
		baseURL:     baseURL,
	}, nil
}

type mockProvider struct {
	id          string
	displayName string
	baseURL     string
}

func (m *mockProvider) ID() string                                              { return m.id }
func (m *mockProvider) DisplayName() string                                     { return m.displayName }
func (m *mockProvider) Icon() string                                            { return "" }
func (m *mockProvider) BrandColor() string                                      { return "" }
func (m *mockProvider) GetAuthURL(ctx context.Context) (string, error)          { return "", nil }
func (m *mockProvider) HandleCallback(ctx context.Context, code string) error   { return nil }
func (m *mockProvider) Disconnect(ctx context.Context) error                    { return nil }
func (m *mockProvider) GetConnectionStatus(ctx context.Context, attemptRefresh bool) (*ConnectionStatus, error) {
	return &ConnectionStatus{}, nil
}
func (m *mockProvider) ListRemoteFiles(ctx context.Context) ([]RemoteFile, error) { return nil, nil }
func (m *mockProvider) DownloadFile(ctx context.Context, fileID string) (*DownloadResult, error) {
	return nil, nil
}

func TestRegistry_Discover_ValidSettings(t *testing.T) {
	tmpDir := t.TempDir()

	// Create root settings.json
	rootSettings := `{"baseUrl": "http://localhost:8080"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), []byte(rootSettings), 0644); err != nil {
		t.Fatal(err)
	}

	// Create provider directory with settings
	providerDir := filepath.Join(tmpDir, "testprovider")
	if err := os.MkdirAll(providerDir, 0755); err != nil {
		t.Fatal(err)
	}
	providerSettings := `{"clientId": "test-client"}`
	if err := os.WriteFile(filepath.Join(providerDir, "settings.json"), []byte(providerSettings), 0644); err != nil {
		t.Fatal(err)
	}

	registry := NewRegistry()
	registry.Register("testprovider", mockFactory)

	providers, err := registry.Discover(tmpDir)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if len(providers) != 1 {
		t.Fatalf("Expected 1 provider, got %d", len(providers))
	}

	if _, ok := providers["testprovider"]; !ok {
		t.Error("Expected testprovider to be discovered")
	}
}

func TestRegistry_Discover_MissingRootSettings(t *testing.T) {
	tmpDir := t.TempDir()

	// No root settings.json

	registry := NewRegistry()
	registry.Register("testprovider", mockFactory)

	_, err := registry.Discover(tmpDir)
	if err == nil {
		t.Error("Expected error when root settings.json is missing")
	}
}

func TestRegistry_Discover_MissingProviderSettings(t *testing.T) {
	tmpDir := t.TempDir()

	// Create root settings.json
	rootSettings := `{"baseUrl": "http://localhost:8080"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), []byte(rootSettings), 0644); err != nil {
		t.Fatal(err)
	}

	// Create provider directory WITHOUT settings
	providerDir := filepath.Join(tmpDir, "testprovider")
	if err := os.MkdirAll(providerDir, 0755); err != nil {
		t.Fatal(err)
	}

	registry := NewRegistry()
	registry.Register("testprovider", mockFactory)

	providers, err := registry.Discover(tmpDir)
	if err != nil {
		t.Fatalf("Discover should not fail: %v", err)
	}

	if len(providers) != 0 {
		t.Errorf("Expected 0 providers (skipped due to missing settings), got %d", len(providers))
	}
}

func TestRegistry_Discover_InvalidProviderSettings(t *testing.T) {
	tmpDir := t.TempDir()

	// Create root settings.json
	rootSettings := `{"baseUrl": "http://localhost:8080"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), []byte(rootSettings), 0644); err != nil {
		t.Fatal(err)
	}

	// Create provider directory with invalid JSON
	providerDir := filepath.Join(tmpDir, "testprovider")
	if err := os.MkdirAll(providerDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(providerDir, "settings.json"), []byte("not valid json"), 0644); err != nil {
		t.Fatal(err)
	}

	// Use a factory that validates JSON
	validatingFactory := func(providerDir, baseURL string, settingsJSON []byte) (SyncableSafesProvider, error) {
		var settings map[string]interface{}
		if err := json.Unmarshal(settingsJSON, &settings); err != nil {
			return nil, err
		}
		return mockFactory(providerDir, baseURL, settingsJSON)
	}

	registry := NewRegistry()
	registry.Register("testprovider", validatingFactory)

	providers, err := registry.Discover(tmpDir)
	if err != nil {
		t.Fatalf("Discover should not fail on invalid provider settings: %v", err)
	}

	if len(providers) != 0 {
		t.Errorf("Expected 0 providers (skipped due to invalid settings), got %d", len(providers))
	}
}

func TestRegistry_Discover_UnknownFolder(t *testing.T) {
	tmpDir := t.TempDir()

	// Create root settings.json
	rootSettings := `{"baseUrl": "http://localhost:8080"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), []byte(rootSettings), 0644); err != nil {
		t.Fatal(err)
	}

	// Create unknown provider directory with settings
	unknownDir := filepath.Join(tmpDir, "unknownprovider")
	if err := os.MkdirAll(unknownDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unknownDir, "settings.json"), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	registry := NewRegistry()
	// Don't register unknownprovider

	providers, err := registry.Discover(tmpDir)
	if err != nil {
		t.Fatalf("Discover should not fail: %v", err)
	}

	if len(providers) != 0 {
		t.Errorf("Expected 0 providers (unknown folder ignored), got %d", len(providers))
	}
}

func TestRegistry_Discover_MultipleProviders(t *testing.T) {
	tmpDir := t.TempDir()

	// Create root settings.json
	rootSettings := `{"baseUrl": "http://localhost:8080"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), []byte(rootSettings), 0644); err != nil {
		t.Fatal(err)
	}

	// Create two provider directories
	for _, name := range []string{"provider1", "provider2"} {
		dir := filepath.Join(tmpDir, name)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{}`), 0644); err != nil {
			t.Fatal(err)
		}
	}

	registry := NewRegistry()
	registry.Register("provider1", mockFactory)
	registry.Register("provider2", mockFactory)

	providers, err := registry.Discover(tmpDir)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if len(providers) != 2 {
		t.Fatalf("Expected 2 providers, got %d", len(providers))
	}
}

func TestRegistry_Discover_BaseURLPassedToFactory(t *testing.T) {
	tmpDir := t.TempDir()

	expectedBaseURL := "http://example.com:9000"

	// Create root settings.json with specific baseUrl
	rootSettings := `{"baseUrl": "` + expectedBaseURL + `"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "settings.json"), []byte(rootSettings), 0644); err != nil {
		t.Fatal(err)
	}

	// Create provider directory
	providerDir := filepath.Join(tmpDir, "testprovider")
	if err := os.MkdirAll(providerDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(providerDir, "settings.json"), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	var capturedBaseURL string
	capturingFactory := func(providerDir, baseURL string, settingsJSON []byte) (SyncableSafesProvider, error) {
		capturedBaseURL = baseURL
		return mockFactory(providerDir, baseURL, settingsJSON)
	}

	registry := NewRegistry()
	registry.Register("testprovider", capturingFactory)

	_, err := registry.Discover(tmpDir)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if capturedBaseURL != expectedBaseURL {
		t.Errorf("Expected baseURL %q, got %q", expectedBaseURL, capturedBaseURL)
	}
}
