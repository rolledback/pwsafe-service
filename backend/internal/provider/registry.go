package provider

import (
	"log"

	"github.com/rolledback/pwsafe-service/backend/internal/config"
	"github.com/rolledback/pwsafe-service/backend/internal/provider/oauthstate"
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

// Discover creates providers based on the settings.json providers map.
// Returns map of providerID -> SyncableSafesProvider for successfully created providers.
func (r *Registry) Discover(settings *config.Settings, dataDir string, oauthStore *oauthstate.Store) (map[string]SyncableSafesProvider, error) {
	providers := make(map[string]SyncableSafesProvider)

	if settings.Providers == nil {
		log.Printf("No providers configured in settings.json")
		return providers, nil
	}

	for providerID, providerConfig := range settings.Providers {
		// Check if we have a factory for this provider
		factory, ok := r.factories[providerID]
		if !ok {
			log.Printf("Warning: unknown provider '%s' in settings.json - skipping", providerID)
			continue
		}

		// Create the provider
		provider, err := factory(providerID, dataDir, settings.BaseURL, providerConfig, oauthStore)
		if err != nil {
			log.Printf("Warning: failed to create %s provider: %v", providerID, err)
			continue
		}

		providers[providerID] = provider
		log.Printf("Discovered provider: %s", providerID)
	}

	return providers, nil
}
