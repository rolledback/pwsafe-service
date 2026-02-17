package provider

import "time"

// RemoteFile represents a file discovered on a remote storage provider
type RemoteFile struct {
	ID           string    // Provider-specific unique identifier
	Name         string    // Display name (e.g., "passwords.psafe3")
	Path         string    // Parent folder path (e.g., "/Documents/Passwords")
	Size         int64     // File size in bytes (0 if unknown)
	LastModified time.Time // Optional: for smarter sync decisions
}

// ConnectionStatus represents the connection/auth state of a provider
type ConnectionStatus struct {
	Connected    bool
	NeedsReauth  bool
	AccountName  string
	AccountEmail string
}

// ProviderFactory creates a provider instance
// providerID: unique identifier (e.g., "onedrive")
// dataDir: base data directory (provider creates its subfolder)
// baseURL: from settings.json, used to construct callback URL
// providerConfig: provider-specific config from settings.json providers map
type ProviderFactory func(providerID string, dataDir string, baseURL string, providerConfig map[string]any) (SyncableSafesProvider, error)
