package service

// SyncConfig stores the persistent state for a provider (saved to .config.json)
type SyncConfig struct {
	Files        []SelectedFile `json:"files"`
	LastSyncTime string         `json:"lastSyncTime,omitempty"`
}

// SelectedFile tracks a file's selection state (provider-agnostic)
type SelectedFile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Selected bool   `json:"selected"`
}

// SyncResult represents the outcome of syncing a single file
type SyncResult struct {
	Name         string `json:"name"`
	Success      bool   `json:"success"`
	LastModified string `json:"lastModified,omitempty"`
	Error        string `json:"error,omitempty"`
}

// ProviderStatus is the full status returned by the API (combines provider + service state)
type ProviderStatus struct {
	ID           string `json:"id"`
	DisplayName  string `json:"displayName"`
	Connected    bool   `json:"connected"`
	NeedsReauth  bool   `json:"needsReauth"`
	AccountName  string `json:"accountName,omitempty"`
	AccountEmail string `json:"accountEmail,omitempty"`
	LastSyncTime string `json:"lastSyncTime,omitempty"`
	NextSyncAt   string `json:"nextSyncAt,omitempty"`
}
