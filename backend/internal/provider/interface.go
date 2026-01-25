package provider

import (
	"context"
	"io"
)

// DownloadResult contains the file content stream and metadata
type DownloadResult struct {
	Content      io.ReadCloser
	LastModified string // From HTTP Last-Modified header
}

// SyncableSafesProvider defines the minimal interface for cloud storage providers.
// Providers implement ONLY the provider-specific primitives.
// All sync orchestration logic lives in the generic SyncableSafesService.
type SyncableSafesProvider interface {
	// Identity
	ID() string          // Unique provider ID (e.g., "onedrive", "gdrive")
	DisplayName() string // Human-readable name (e.g., "OneDrive", "Google Drive")

	// Auth lifecycle
	GetAuthURL(ctx context.Context) (string, error)
	HandleCallback(ctx context.Context, code string) error
	Disconnect(ctx context.Context) error
	GetConnectionStatus(ctx context.Context, attemptRefresh bool) (*ConnectionStatus, error)

	// Remote operations - the ONLY provider-specific sync primitives
	ListRemoteFiles(ctx context.Context) ([]RemoteFile, error)
	DownloadFile(ctx context.Context, fileID string) (*DownloadResult, error)
}
