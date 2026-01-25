package mock

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/rolledback/pwsafe-service/backend/internal/provider"
)

func TestProvider_ImplementsInterface(t *testing.T) {
	var _ provider.SyncableSafesProvider = (*Provider)(nil)
}

func TestProvider_Identity(t *testing.T) {
	p := NewProvider("test")

	if p.ID() != "test" {
		t.Errorf("Expected ID 'test', got '%s'", p.ID())
	}

	if p.DisplayName() != "Mock test" {
		t.Errorf("Expected DisplayName 'Mock test', got '%s'", p.DisplayName())
	}
}

func TestProvider_DefaultConnected(t *testing.T) {
	p := NewProvider("test")
	ctx := context.Background()

	status, err := p.GetConnectionStatus(ctx, false)
	if err != nil {
		t.Fatalf("GetConnectionStatus failed: %v", err)
	}

	if !status.Connected {
		t.Error("Expected Connected=true by default")
	}
}

func TestProvider_SetConnected(t *testing.T) {
	p := NewProvider("test")
	ctx := context.Background()

	p.SetConnected(false)
	status, _ := p.GetConnectionStatus(ctx, false)
	if status.Connected {
		t.Error("Expected Connected=false after SetConnected(false)")
	}

	p.SetConnected(true)
	status, _ = p.GetConnectionStatus(ctx, false)
	if !status.Connected {
		t.Error("Expected Connected=true after SetConnected(true)")
	}
}

func TestProvider_GetAuthURL(t *testing.T) {
	p := NewProvider("myid")
	ctx := context.Background()

	url, err := p.GetAuthURL(ctx)
	if err != nil {
		t.Fatalf("GetAuthURL failed: %v", err)
	}

	if url != "https://mock.auth.url/myid" {
		t.Errorf("Expected URL with provider ID, got '%s'", url)
	}
}

func TestProvider_GetAuthURL_Error(t *testing.T) {
	p := NewProvider("test")
	p.AuthError = fmt.Errorf("auth failed")
	ctx := context.Background()

	_, err := p.GetAuthURL(ctx)
	if err == nil {
		t.Error("Expected error from GetAuthURL")
	}
}

func TestProvider_HandleCallback(t *testing.T) {
	p := NewProvider("test")
	p.SetConnected(false)
	ctx := context.Background()

	err := p.HandleCallback(ctx, "auth-code")
	if err != nil {
		t.Fatalf("HandleCallback failed: %v", err)
	}

	status, _ := p.GetConnectionStatus(ctx, false)
	if !status.Connected {
		t.Error("Expected Connected=true after HandleCallback")
	}
}

func TestProvider_Disconnect(t *testing.T) {
	p := NewProvider("test")
	ctx := context.Background()

	if p.DisconnectCalls != 0 {
		t.Error("Expected 0 DisconnectCalls initially")
	}

	p.Disconnect(ctx)

	if p.DisconnectCalls != 1 {
		t.Errorf("Expected 1 DisconnectCall, got %d", p.DisconnectCalls)
	}

	status, _ := p.GetConnectionStatus(ctx, false)
	if status.Connected {
		t.Error("Expected Connected=false after Disconnect")
	}
}

func TestProvider_ListRemoteFiles(t *testing.T) {
	p := NewProvider("test")
	ctx := context.Background()

	// Empty by default
	files, err := p.ListRemoteFiles(ctx)
	if err != nil {
		t.Fatalf("ListRemoteFiles failed: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("Expected 0 files, got %d", len(files))
	}

	// Set files
	p.SetFiles([]provider.RemoteFile{
		{ID: "f1", Name: "test.psafe3", Path: "/"},
		{ID: "f2", Name: "other.psafe3", Path: "/Documents"},
	})

	files, err = p.ListRemoteFiles(ctx)
	if err != nil {
		t.Fatalf("ListRemoteFiles failed: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("Expected 2 files, got %d", len(files))
	}
}

func TestProvider_ListRemoteFiles_Error(t *testing.T) {
	p := NewProvider("test")
	p.ListError = fmt.Errorf("network error")
	ctx := context.Background()

	_, err := p.ListRemoteFiles(ctx)
	if err == nil {
		t.Error("Expected error from ListRemoteFiles")
	}
}

func TestProvider_DownloadFile(t *testing.T) {
	p := NewProvider("test")
	p.SetContent("f1", []byte("file content"))
	ctx := context.Background()

	result, err := p.DownloadFile(ctx, "f1")
	if err != nil {
		t.Fatalf("DownloadFile failed: %v", err)
	}
	defer result.Content.Close()

	content, _ := io.ReadAll(result.Content)
	if string(content) != "file content" {
		t.Errorf("Expected 'file content', got '%s'", string(content))
	}

	if result.LastModified == "" {
		t.Error("Expected LastModified to be set")
	}

	// Verify tracking
	if len(p.DownloadedFiles) != 1 || p.DownloadedFiles[0] != "f1" {
		t.Errorf("Expected DownloadedFiles=['f1'], got %v", p.DownloadedFiles)
	}
}

func TestProvider_DownloadFile_NotFound(t *testing.T) {
	p := NewProvider("test")
	ctx := context.Background()

	_, err := p.DownloadFile(ctx, "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestProvider_DownloadFile_Error(t *testing.T) {
	p := NewProvider("test")
	p.SetContent("f1", []byte("content"))
	p.DownloadError = fmt.Errorf("download failed")
	ctx := context.Background()

	_, err := p.DownloadFile(ctx, "f1")
	if err == nil {
		t.Error("Expected error from DownloadFile")
	}
}
