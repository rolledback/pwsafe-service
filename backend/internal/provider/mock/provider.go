package mock

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/rolledback/pwsafe-service/backend/internal/provider"
)

// Provider implements provider.SyncableSafesProvider for testing
type Provider struct {
	id         string
	name       string
	icon       string
	brandColor string
	files      []provider.RemoteFile
	content    map[string][]byte // fileID -> content
	status     *provider.ConnectionStatus

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
		icon:       "data:image/svg+xml;base64,mock-icon",
		brandColor: "#888888",
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
	return "https://mock.auth.url/" + p.id, nil
}

func (p *Provider) HandleCallback(ctx context.Context, code string) error {
	if p.AuthError != nil {
		return p.AuthError
	}
	p.status.Connected = true
	return nil
}

func (p *Provider) Disconnect(ctx context.Context) error {
	p.DisconnectCalls++
	p.status.Connected = false
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
