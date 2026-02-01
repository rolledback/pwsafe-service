package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/rolledback/pwsafe-service/backend/internal/config"
)

// mockFactory creates a simple mock provider for testing
func mockFactory(providerID string, dataDir string, baseURL string, providerConfig map[string]any) (SyncableSafesProvider, error) {
	return &mockProvider{
		id:          providerID,
		displayName: "Mock " + providerID,
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

	settings := &config.Settings{
		BaseURL: "http://localhost:8080",
		Providers: map[string]map[string]any{
			"testprovider": {"clientId": "test-client"},
		},
	}

	registry := NewRegistry()
	registry.Register("testprovider", mockFactory)

	providers, err := registry.Discover(settings, tmpDir)
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

func TestRegistry_Discover_NoProviders(t *testing.T) {
	tmpDir := t.TempDir()

	settings := &config.Settings{
		BaseURL:   "http://localhost:8080",
		Providers: nil,
	}

	registry := NewRegistry()
	registry.Register("testprovider", mockFactory)

	providers, err := registry.Discover(settings, tmpDir)
	if err != nil {
		t.Fatalf("Discover should not fail: %v", err)
	}

	if len(providers) != 0 {
		t.Errorf("Expected 0 providers (no providers configured), got %d", len(providers))
	}
}

func TestRegistry_Discover_FactoryError(t *testing.T) {
	tmpDir := t.TempDir()

	settings := &config.Settings{
		BaseURL: "http://localhost:8080",
		Providers: map[string]map[string]any{
			"testprovider": {"clientId": "test-client"},
		},
	}

	// Use a factory that returns an error
	failingFactory := func(providerID string, dataDir string, baseURL string, providerConfig map[string]any) (SyncableSafesProvider, error) {
		return nil, errors.New("factory error")
	}

	registry := NewRegistry()
	registry.Register("testprovider", failingFactory)

	providers, err := registry.Discover(settings, tmpDir)
	if err != nil {
		t.Fatalf("Discover should not fail on factory error: %v", err)
	}

	if len(providers) != 0 {
		t.Errorf("Expected 0 providers (skipped due to factory error), got %d", len(providers))
	}
}

func TestRegistry_Discover_UnknownProvider(t *testing.T) {
	tmpDir := t.TempDir()

	settings := &config.Settings{
		BaseURL: "http://localhost:8080",
		Providers: map[string]map[string]any{
			"unknownprovider": {},
		},
	}

	registry := NewRegistry()
	// Don't register unknownprovider

	providers, err := registry.Discover(settings, tmpDir)
	if err != nil {
		t.Fatalf("Discover should not fail: %v", err)
	}

	if len(providers) != 0 {
		t.Errorf("Expected 0 providers (unknown provider ignored), got %d", len(providers))
	}
}

func TestRegistry_Discover_MultipleProviders(t *testing.T) {
	tmpDir := t.TempDir()

	settings := &config.Settings{
		BaseURL: "http://localhost:8080",
		Providers: map[string]map[string]any{
			"provider1": {},
			"provider2": {},
		},
	}

	registry := NewRegistry()
	registry.Register("provider1", mockFactory)
	registry.Register("provider2", mockFactory)

	providers, err := registry.Discover(settings, tmpDir)
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

	settings := &config.Settings{
		BaseURL: expectedBaseURL,
		Providers: map[string]map[string]any{
			"testprovider": {},
		},
	}

	var capturedBaseURL string
	capturingFactory := func(providerID string, dataDir string, baseURL string, providerConfig map[string]any) (SyncableSafesProvider, error) {
		capturedBaseURL = baseURL
		return mockFactory(providerID, dataDir, baseURL, providerConfig)
	}

	registry := NewRegistry()
	registry.Register("testprovider", capturingFactory)

	_, err := registry.Discover(settings, tmpDir)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if capturedBaseURL != expectedBaseURL {
		t.Errorf("Expected baseURL %q, got %q", expectedBaseURL, capturedBaseURL)
	}
}
