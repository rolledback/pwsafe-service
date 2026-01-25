package provider

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Registry manages provider discovery and creation
type Registry struct {
	factories map[string]ProviderFactory
}

// NewRegistry creates a new provider registry
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]ProviderFactory),
	}
}

// Register adds a provider factory for a given provider ID
func (r *Registry) Register(providerID string, factory ProviderFactory) {
	r.factories[providerID] = factory
}

// Discover scans safesDir for valid provider configs and creates providers.
// Returns map of providerID -> SyncableSafesProvider for successfully created providers.
func (r *Registry) Discover(safesDir string) (map[string]SyncableSafesProvider, error) {
	// Step 1: Read root settings.json for baseURL
	rootSettingsPath := filepath.Join(safesDir, "settings.json")
	rootData, err := os.ReadFile(rootSettingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("settings.json not found in %s: baseUrl is required", safesDir)
		}
		return nil, fmt.Errorf("failed to read settings.json: %w", err)
	}

	var rootSettings RootSettings
	if err := json.Unmarshal(rootData, &rootSettings); err != nil {
		return nil, fmt.Errorf("invalid settings.json: %w", err)
	}

	if rootSettings.BaseURL == "" {
		return nil, fmt.Errorf("baseUrl is required in settings.json")
	}

	// Step 2: Scan for provider subdirectories
	providers := make(map[string]SyncableSafesProvider)

	entries, err := os.ReadDir(safesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read safes directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		providerID := entry.Name()

		// Check if we have a factory for this provider
		factory, ok := r.factories[providerID]
		if !ok {
			// Unknown provider folder - ignore it
			continue
		}

		// Check for settings.json in provider folder
		providerDir := filepath.Join(safesDir, providerID)
		settingsPath := filepath.Join(providerDir, "settings.json")

		settingsData, err := os.ReadFile(settingsPath)
		if err != nil {
			if os.IsNotExist(err) {
				// No settings.json - skip this provider silently
				continue
			}
			log.Printf("Warning: failed to read %s: %v", settingsPath, err)
			continue
		}

		// Try to create the provider
		provider, err := factory(providerDir, rootSettings.BaseURL, settingsData)
		if err != nil {
			log.Printf("Warning: failed to create %s provider: %v", providerID, err)
			continue
		}

		providers[providerID] = provider
		log.Printf("Discovered provider: %s", providerID)
	}

	return providers, nil
}
