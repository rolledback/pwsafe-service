package mock

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rolledback/pwsafe-service/backend/internal/provider"
)

const (
	// Mock provider brand color (teal)
	mockBrandColor = "#00B294"

	// Test tube emoji rendered as SVG data URL (sized to match other provider icons)
	mockIcon = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHRleHQgeD0iNTAlIiB5PSI1MCUiIGRvbWluYW50LWJhc2VsaW5lPSJjZW50cmFsIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjI4Ij7wn6eqPC90ZXh0Pjwvc3ZnPg=="

	// Simulated delay for mock operations
	mockDelay = 3 * time.Second
)

// Factory creates a mock provider from the settings.json providers config.
// It scans the testdata/ directory for .psafe3 files and serves them.
func Factory(providerID string, dataDir string, baseURL string, providerConfig map[string]any) (provider.SyncableSafesProvider, error) {
	// Build callback URL from baseURL
	callbackURL := strings.TrimSuffix(baseURL, "/") + "/api/providers/" + providerID + "/auth/callback"

	p := &Provider{
		id:          providerID,
		name:        "Mock Provider",
		icon:        mockIcon,
		brandColor:  mockBrandColor,
		callbackURL: callbackURL,
		files:       []provider.RemoteFile{},
		content:     make(map[string][]byte),
		status:      &provider.ConnectionStatus{Connected: false}, // Start disconnected
	}

	// Scan testdata/ for .psafe3 files
	testdataDir := "testdata"
	entries, err := os.ReadDir(testdataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read testdata directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".psafe3") {
			continue
		}

		filePath := filepath.Join(testdataDir, entry.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", filePath, err)
		}

		fileID := entry.Name() // Use filename as ID
		p.files = append(p.files, provider.RemoteFile{
			ID:   fileID,
			Name: entry.Name(),
			Path: "/",
		})
		p.content[fileID] = content
	}

	return p, nil
}

// Provider implements provider.SyncableSafesProvider for testing
type Provider struct {
	id          string
	name        string
	icon        string
	brandColor  string
	callbackURL string // For Factory-created providers to enable auth flow
	files       []provider.RemoteFile
	content     map[string][]byte // fileID -> content
	status      *provider.ConnectionStatus

	// Error simulation
	ListError     error
	DownloadError error
	AuthError     error

	// Call tracking
	DownloadedFiles []string
	DisconnectCalls int
}

// NewProvider creates a new mock provider for testing
func NewProvider(id string) *Provider {
	return &Provider{
		id:         id,
		name:       "Mock " + id,
		icon:       mockIcon,
		brandColor: mockBrandColor,
		files:      []provider.RemoteFile{},
		content:    make(map[string][]byte),
		status:     &provider.ConnectionStatus{Connected: true},
	}
}

// SetFiles sets the remote files that will be returned by ListRemoteFiles
func (p *Provider) SetFiles(files []provider.RemoteFile) {
	p.files = files
}

// SetContent sets the content for a file ID
func (p *Provider) SetContent(fileID string, content []byte) {
	p.content[fileID] = content
}

// SetConnected sets the connection status
func (p *Provider) SetConnected(connected bool) {
	p.status.Connected = connected
}

// SetStatus sets the full connection status
func (p *Provider) SetStatus(status *provider.ConnectionStatus) {
	p.status = status
}

// SetIcon sets the provider icon
func (p *Provider) SetIcon(icon string) {
	p.icon = icon
}

// SetBrandColor sets the provider brand color
func (p *Provider) SetBrandColor(color string) {
	p.brandColor = color
}

// ============ IDENTITY ============

func (p *Provider) ID() string {
	return p.id
}

func (p *Provider) DisplayName() string {
	return p.name
}

// ============ METADATA ============

func (p *Provider) Icon() string {
	return p.icon
}

func (p *Provider) BrandColor() string {
	return p.brandColor
}

// ============ AUTH ============

func (p *Provider) GetAuthURL(ctx context.Context) (string, error) {
	if p.AuthError != nil {
		return "", p.AuthError
	}
	// If we have a callback URL (Factory-created), redirect directly to it with a mock code
	if p.callbackURL != "" {
		return p.callbackURL + "?code=mock-auth-code", nil
	}
	// Fallback for test-created providers
	return "https://mock.auth.url/" + p.id, nil
}

func (p *Provider) HandleCallback(ctx context.Context, code string, state string) error {
	if p.AuthError != nil {
		return p.AuthError
	}
	// Simulate network delay for auth
	time.Sleep(mockDelay)
	p.status.Connected = true
	p.status.NeedsReauth = false
	return nil
}

func (p *Provider) Disconnect(ctx context.Context) error {
	p.DisconnectCalls++
	p.status.Connected = false
	p.status.NeedsReauth = false
	return nil
}

func (p *Provider) GetConnectionStatus(ctx context.Context, attemptRefresh bool) (*provider.ConnectionStatus, error) {
	return p.status, nil
}

// ============ REMOTE OPERATIONS ============

func (p *Provider) ListRemoteFiles(ctx context.Context) ([]provider.RemoteFile, error) {
	if p.ListError != nil {
		return nil, p.ListError
	}
	// Simulate network delay for sync
	time.Sleep(mockDelay)
	return p.files, nil
}

func (p *Provider) DownloadFile(ctx context.Context, fileID string) (*provider.DownloadResult, error) {
	if p.DownloadError != nil {
		return nil, p.DownloadError
	}

	content, ok := p.content[fileID]
	if !ok {
		return nil, fmt.Errorf("file not found: %s", fileID)
	}

	p.DownloadedFiles = append(p.DownloadedFiles, fileID)

	// Return an in-memory reader - no filesystem needed!
	return &provider.DownloadResult{
		Content:      io.NopCloser(bytes.NewReader(content)),
		LastModified: "Mon, 24 Jan 2026 12:00:00 GMT",
	}, nil
}
