package provider

import "time"

// RemoteFile represents a file discovered on a remote storage provider
type RemoteFile struct {
	ID           string    // Provider-specific unique identifier
	Name         string    // Display name (e.g., "passwords.psafe3")
	Path         string    // Parent folder path (e.g., "/Documents/Passwords")
	LastModified time.Time // Optional: for smarter sync decisions
}

// ConnectionStatus represents the connection/auth state of a provider
type ConnectionStatus struct {
	Connected    bool
	NeedsReauth  bool
	AccountName  string
	AccountEmail string
}
