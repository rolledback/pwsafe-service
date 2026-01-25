package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rolledback/pwsafe-service/backend/internal/provider"
	"github.com/rolledback/pwsafe-service/backend/internal/provider/mock"
)

func TestSync_DownloadsSelectedFiles(t *testing.T) {
	tempDir := t.TempDir()

	mockProvider := mock.NewProvider("mock")
	mockProvider.SetFiles([]provider.RemoteFile{
		{ID: "f1", Name: "test.psafe3", Path: "/"},
	})
	mockProvider.SetContent("f1", []byte("safe content"))

	ctx := context.Background()
	svc := NewSyncableSafesService(ctx, tempDir, mockProvider)
	defer svc.Stop()

	// Select the file
	err := svc.SaveFiles([]SelectedFile{
		{ID: "f1", Name: "test.psafe3", Path: "/", Selected: true},
	})
	if err != nil {
		t.Fatalf("SaveFiles failed: %v", err)
	}

	// Sync
	results, err := svc.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	if !results[0].Success {
		t.Errorf("Expected sync success, got error: %s", results[0].Error)
	}

	// Verify file exists
	content, err := os.ReadFile(filepath.Join(tempDir, "mock", "test.psafe3"))
	if err != nil {
		t.Fatalf("Failed to read synced file: %v", err)
	}

	if string(content) != "safe content" {
		t.Errorf("Expected 'safe content', got '%s'", string(content))
	}

	// Verify download was tracked
	if len(mockProvider.DownloadedFiles) != 1 || mockProvider.DownloadedFiles[0] != "f1" {
		t.Errorf("Expected download of f1, got %v", mockProvider.DownloadedFiles)
	}
}

func TestSync_CleansUpUnselectedFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Pre-create a file that will be "unselected"
	mockDir := filepath.Join(tempDir, "mock")
	os.MkdirAll(mockDir, 0755)
	os.WriteFile(filepath.Join(mockDir, "old.psafe3"), []byte("old content"), 0644)

	mockProvider := mock.NewProvider("mock")
	mockProvider.SetFiles([]provider.RemoteFile{}) // No remote files

	ctx := context.Background()
	svc := NewSyncableSafesService(ctx, tempDir, mockProvider)
	defer svc.Stop()

	// Sync with nothing selected
	svc.Sync(ctx)

	// Old file should be deleted
	_, err := os.Stat(filepath.Join(mockDir, "old.psafe3"))
	if !os.IsNotExist(err) {
		t.Error("Expected old.psafe3 to be deleted")
	}
}

func TestSync_UpdatesLastSyncTime(t *testing.T) {
	tempDir := t.TempDir()

	mockProvider := mock.NewProvider("mock")

	ctx := context.Background()
	svc := NewSyncableSafesService(ctx, tempDir, mockProvider)
	defer svc.Stop()

	// Sync
	svc.Sync(ctx)

	// Verify config was updated
	config, err := svc.loadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.LastSyncTime == "" {
		t.Error("Expected LastSyncTime to be set")
	}
}

func TestListFiles_MergesWithSavedSelections(t *testing.T) {
	tempDir := t.TempDir()

	mockProvider := mock.NewProvider("mock")
	mockProvider.SetFiles([]provider.RemoteFile{
		{ID: "f1", Name: "a.psafe3", Path: "/"},
		{ID: "f2", Name: "b.psafe3", Path: "/"},
	})

	ctx := context.Background()
	svc := NewSyncableSafesService(ctx, tempDir, mockProvider)
	defer svc.Stop()

	// Pre-save selection for f1
	err := svc.SaveFiles([]SelectedFile{
		{ID: "f1", Name: "a.psafe3", Path: "/", Selected: true},
	})
	if err != nil {
		t.Fatalf("SaveFiles failed: %v", err)
	}

	// List should merge
	files, err := svc.ListFiles(ctx)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("Expected 2 files, got %d", len(files))
	}

	// Find f1 and f2 in results
	var f1Selected, f2Selected bool
	for _, f := range files {
		if f.ID == "f1" {
			f1Selected = f.Selected
		}
		if f.ID == "f2" {
			f2Selected = f.Selected
		}
	}

	if !f1Selected {
		t.Error("Expected f1 to be selected")
	}
	if f2Selected {
		t.Error("Expected f2 to NOT be selected")
	}
}

func TestGetProviderStatus_ReturnsCorrectInfo(t *testing.T) {
	tempDir := t.TempDir()

	mockProvider := mock.NewProvider("mock")
	mockProvider.SetStatus(&provider.ConnectionStatus{
		Connected:    true,
		AccountName:  "Test User",
		AccountEmail: "test@example.com",
	})

	ctx := context.Background()
	svc := NewSyncableSafesService(ctx, tempDir, mockProvider)
	defer svc.Stop()

	status, err := svc.GetProviderStatus(ctx)
	if err != nil {
		t.Fatalf("GetProviderStatus failed: %v", err)
	}

	if status.ID != "mock" {
		t.Errorf("Expected ID 'mock', got '%s'", status.ID)
	}
	if !status.Connected {
		t.Error("Expected Connected to be true")
	}
	if status.AccountName != "Test User" {
		t.Errorf("Expected AccountName 'Test User', got '%s'", status.AccountName)
	}
	if status.AccountEmail != "test@example.com" {
		t.Errorf("Expected AccountEmail 'test@example.com', got '%s'", status.AccountEmail)
	}
	if status.NextSyncAt == "" {
		t.Error("Expected NextSyncAt to be set")
	}
}

func TestDisconnect_CleansUpFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Pre-create some files
	mockDir := filepath.Join(tempDir, "mock")
	os.MkdirAll(mockDir, 0755)
	os.WriteFile(filepath.Join(mockDir, "test.psafe3"), []byte("content"), 0644)
	os.WriteFile(filepath.Join(mockDir, ".config.json"), []byte("{}"), 0644)

	mockProvider := mock.NewProvider("mock")

	ctx := context.Background()
	svc := NewSyncableSafesService(ctx, tempDir, mockProvider)
	defer svc.Stop()

	// Disconnect
	err := svc.Disconnect(ctx)
	if err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}

	// Safe file should be deleted
	_, err = os.Stat(filepath.Join(mockDir, "test.psafe3"))
	if !os.IsNotExist(err) {
		t.Error("Expected test.psafe3 to be deleted")
	}

	// Config should be deleted
	_, err = os.Stat(filepath.Join(mockDir, ".config.json"))
	if !os.IsNotExist(err) {
		t.Error("Expected .config.json to be deleted")
	}

	// Provider's Disconnect should have been called
	if mockProvider.DisconnectCalls != 1 {
		t.Errorf("Expected 1 Disconnect call, got %d", mockProvider.DisconnectCalls)
	}
}

func TestSync_HandlesDownloadError(t *testing.T) {
	tempDir := t.TempDir()

	mockProvider := mock.NewProvider("mock")
	mockProvider.SetFiles([]provider.RemoteFile{
		{ID: "f1", Name: "test.psafe3", Path: "/"},
	})
	// Don't set content - this will cause a "file not found" error

	ctx := context.Background()
	svc := NewSyncableSafesService(ctx, tempDir, mockProvider)
	defer svc.Stop()

	// Select the file
	svc.SaveFiles([]SelectedFile{
		{ID: "f1", Name: "test.psafe3", Path: "/", Selected: true},
	})

	// Sync should not fail, but result should show error
	results, err := svc.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync should not return error, got: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	if results[0].Success {
		t.Error("Expected sync to fail for this file")
	}

	if results[0].Error == "" {
		t.Error("Expected error message in result")
	}
}

func TestSync_PreservesPathStructure(t *testing.T) {
	tempDir := t.TempDir()

	mockProvider := mock.NewProvider("mock")
	mockProvider.SetFiles([]provider.RemoteFile{
		{ID: "f1", Name: "deep.psafe3", Path: "/Documents/Passwords"},
	})
	mockProvider.SetContent("f1", []byte("deep content"))

	ctx := context.Background()
	svc := NewSyncableSafesService(ctx, tempDir, mockProvider)
	defer svc.Stop()

	// Select the file
	svc.SaveFiles([]SelectedFile{
		{ID: "f1", Name: "deep.psafe3", Path: "/Documents/Passwords", Selected: true},
	})

	// Sync
	svc.Sync(ctx)

	// Verify file is at correct nested path
	expectedPath := filepath.Join(tempDir, "mock", "Documents", "Passwords", "deep.psafe3")
	content, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("Failed to read file at expected path %s: %v", expectedPath, err)
	}

	if string(content) != "deep content" {
		t.Errorf("Expected 'deep content', got '%s'", string(content))
	}
}

func TestSync_FailsWhenNotConnected(t *testing.T) {
	tempDir := t.TempDir()

	mockProvider := mock.NewProvider("mock")
	mockProvider.SetConnected(false) // Not connected

	ctx := context.Background()
	svc := NewSyncableSafesService(ctx, tempDir, mockProvider)
	defer svc.Stop()

	// Sync should fail with auth error
	_, err := svc.Sync(ctx)
	if err == nil {
		t.Error("Expected error when not connected")
	}
	if err.Error() != "not authenticated" {
		t.Errorf("Expected 'not authenticated' error, got: %v", err)
	}
}

func TestSync_ReturnsLastModified(t *testing.T) {
	tempDir := t.TempDir()

	mockProvider := mock.NewProvider("mock")
	mockProvider.SetFiles([]provider.RemoteFile{
		{ID: "f1", Name: "test.psafe3", Path: "/"},
	})
	mockProvider.SetContent("f1", []byte("content"))

	ctx := context.Background()
	svc := NewSyncableSafesService(ctx, tempDir, mockProvider)
	defer svc.Stop()

	// Select the file
	svc.SaveFiles([]SelectedFile{
		{ID: "f1", Name: "test.psafe3", Path: "/", Selected: true},
	})

	// Sync
	results, err := svc.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	// FakeProvider returns a mock LastModified value
	if results[0].LastModified == "" {
		t.Error("Expected LastModified to be populated")
	}
}
