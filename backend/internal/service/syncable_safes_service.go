package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rolledback/pwsafe-service/backend/internal/provider"
)

const defaultSyncInterval = 15 * time.Minute

// SyncableSafesService orchestrates sync for ANY provider.
// All sync logic lives here - providers only implement primitives.
type SyncableSafesService struct {
	safesDirectory string
	provider       provider.SyncableSafesProvider

	syncMutex      sync.RWMutex
	nextSyncMutex  sync.RWMutex
	nextSyncAt     time.Time
	syncInterval   time.Duration

	ctx    context.Context
	cancel context.CancelFunc
}

// NewSyncableSafesService creates a sync service for a single provider
func NewSyncableSafesService(
	ctx context.Context,
	safesDirectory string,
	p provider.SyncableSafesProvider,
) *SyncableSafesService {
	ctx, cancel := context.WithCancel(ctx)
	svc := &SyncableSafesService{
		safesDirectory: safesDirectory,
		provider:       p,
		syncInterval:   defaultSyncInterval,
		nextSyncAt:     time.Now().Add(defaultSyncInterval),
		ctx:            ctx,
		cancel:         cancel,
	}
	go svc.periodicSync()
	return svc
}

// Stop gracefully shuts down the sync loop
func (s *SyncableSafesService) Stop() {
	s.cancel()
}

// Provider returns the underlying provider (for auth flow delegation)
func (s *SyncableSafesService) Provider() provider.SyncableSafesProvider {
	return s.provider
}

// GetProviderStatus returns the provider status merged with sync timing
func (s *SyncableSafesService) GetProviderStatus(ctx context.Context) (*ProviderStatus, error) {
	s.syncMutex.RLock()
	defer s.syncMutex.RUnlock()

	status, err := s.provider.GetConnectionStatus(ctx, true) // attemptRefresh=true for accurate status
	if err != nil {
		return nil, err
	}

	config, _ := s.loadConfig()

	s.nextSyncMutex.RLock()
	nextSyncAt := s.nextSyncAt.Format(time.RFC3339)
	s.nextSyncMutex.RUnlock()

	return &ProviderStatus{
		ID:           s.provider.ID(),
		DisplayName:  s.provider.DisplayName(),
		Connected:    status.Connected,
		NeedsReauth:  status.NeedsReauth,
		AccountName:  status.AccountName,
		AccountEmail: status.AccountEmail,
		LastSyncTime: config.LastSyncTime,
		NextSyncAt:   nextSyncAt,
	}, nil
}

// ListFiles returns remote files merged with saved selection state
func (s *SyncableSafesService) ListFiles(ctx context.Context) ([]SelectedFile, error) {
	// Load saved config
	config, _ := s.loadConfig()
	savedSelections := make(map[string]bool)
	for _, f := range config.Files {
		savedSelections[f.ID] = f.Selected
	}

	// Fetch remote files
	remoteFiles, err := s.provider.ListRemoteFiles(ctx)
	if err != nil {
		// Return cached files if remote unavailable
		return config.Files, nil
	}

	// Merge: remote files + saved selection state
	var result []SelectedFile
	for _, rf := range remoteFiles {
		result = append(result, SelectedFile{
			ID:       rf.ID,
			Name:     rf.Name,
			Path:     rf.Path,
			Selected: savedSelections[rf.ID],
		})
	}

	return result, nil
}

// SaveFiles persists file selection state
func (s *SyncableSafesService) SaveFiles(files []SelectedFile) error {
	config, _ := s.loadConfig()
	config.Files = files
	return s.saveConfig(config)
}

// Sync performs the sync operation
// THIS IS THE CORE GENERIC SYNC ALGORITHM
func (s *SyncableSafesService) Sync(ctx context.Context) ([]SyncResult, error) {
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()

	// Step 0: Verify we're connected before starting
	status, err := s.provider.GetConnectionStatus(ctx, false) // cheap check, refresh happens in API calls
	if err != nil {
		return nil, fmt.Errorf("failed to check connection status: %w", err)
	}
	if !status.Connected {
		return nil, fmt.Errorf("not authenticated")
	}

	// Step 1: Load config (which files are selected)
	config, err := s.loadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Get selected files
	var selectedFiles []SelectedFile
	for _, f := range config.Files {
		if f.Selected {
			selectedFiles = append(selectedFiles, f)
		}
	}

	var results []SyncResult

	// Step 2: For each selected file, download from remote
	for _, file := range selectedFiles {
		localPath := s.getLocalPath(file)
		result := SyncResult{Name: file.Name, Success: false}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(localPath), 0700); err != nil {
			result.Error = fmt.Sprintf("failed to create directory: %v", err)
			results = append(results, result)
			continue
		}

		// Download via provider primitive (returns DownloadResult with LastModified)
		lastModified, err := s.downloadToPath(ctx, file.ID, localPath)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
			result.LastModified = lastModified
		}
		results = append(results, result)
	}

	// Step 3: Cleanup files no longer selected
	s.cleanupUnselectedFiles(selectedFiles)

	// Step 4: Update LastSyncTime
	config.LastSyncTime = time.Now().Format(time.RFC3339)
	s.saveConfig(config)

	// Step 5: Next sync scheduled by periodic loop

	return results, nil
}

// Disconnect removes provider connection and cleans up
func (s *SyncableSafesService) Disconnect(ctx context.Context) error {
	// Let provider clean up its auth state (tokens)
	if err := s.provider.Disconnect(ctx); err != nil {
		return err
	}

	// Clean up generic state (config + synced files)
	os.Remove(s.configPath())
	s.cleanupAllSafeFiles()

	return nil
}

// ============ PRIVATE HELPER METHODS (all generic) ============

func (s *SyncableSafesService) periodicSync() {
	ticker := time.NewTicker(s.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("%s: periodic sync stopped", s.provider.ID())
			return
		case <-ticker.C:
			s.tryPeriodicSync()
			s.nextSyncMutex.Lock()
			s.nextSyncAt = time.Now().Add(s.syncInterval)
			s.nextSyncMutex.Unlock()
		}
	}
}

func (s *SyncableSafesService) tryPeriodicSync() {
	status, err := s.provider.GetConnectionStatus(s.ctx, false) // cheap check
	if err != nil || !status.Connected {
		return // Skip if not connected
	}

	log.Printf("%s: starting periodic sync", s.provider.ID())
	results, err := s.Sync(s.ctx)
	if err != nil {
		log.Printf("%s: periodic sync failed: %v", s.provider.ID(), err)
	} else {
		successCount := 0
		for _, r := range results {
			if r.Success {
				successCount++
			}
		}
		log.Printf("%s: periodic sync completed (%d/%d files)", s.provider.ID(), successCount, len(results))
	}
}

func (s *SyncableSafesService) providerDir() string {
	return filepath.Join(s.safesDirectory, s.provider.ID())
}

func (s *SyncableSafesService) configPath() string {
	return filepath.Join(s.providerDir(), ".config.json")
}

func (s *SyncableSafesService) loadConfig() (*SyncConfig, error) {
	data, err := os.ReadFile(s.configPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &SyncConfig{Files: []SelectedFile{}}, nil
		}
		return nil, err
	}
	var config SyncConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (s *SyncableSafesService) saveConfig(config *SyncConfig) error {
	if err := os.MkdirAll(s.providerDir(), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.configPath(), data, 0600)
}

func (s *SyncableSafesService) getLocalPath(file SelectedFile) string {
	relativePath := filepath.FromSlash(file.Path)
	relativePath = strings.TrimPrefix(relativePath, string(filepath.Separator))
	return filepath.Join(s.providerDir(), relativePath, file.Name)
}

// downloadToPath handles atomic file writing from provider stream
// Returns the LastModified header value from the download
func (s *SyncableSafesService) downloadToPath(ctx context.Context, fileID, localPath string) (string, error) {
	// Get stream from provider
	result, err := s.provider.DownloadFile(ctx, fileID)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer result.Content.Close()

	// Write to temp file first (atomic write)
	tmpPath := localPath + ".tmp"
	file, err := os.Create(tmpPath)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}

	if _, err := io.Copy(file, result.Content); err != nil {
		file.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to write file: %w", err)
	}
	file.Close()

	// Atomic rename
	if err := os.Rename(tmpPath, localPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to finalize file: %w", err)
	}

	return result.LastModified, nil
}

func (s *SyncableSafesService) cleanupUnselectedFiles(selectedFiles []SelectedFile) {
	selectedPaths := make(map[string]bool)
	for _, f := range selectedFiles {
		selectedPaths[s.getLocalPath(f)] = true
	}

	providerDir := s.providerDir()
	filepath.WalkDir(providerDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".psafe3") {
			if !selectedPaths[path] {
				if os.Remove(path) == nil {
					s.cleanupEmptyParentDirs(filepath.Dir(path), providerDir)
				}
			}
		}
		return nil
	})
}

func (s *SyncableSafesService) cleanupAllSafeFiles() {
	providerDir := s.providerDir()
	if _, err := os.Stat(providerDir); os.IsNotExist(err) {
		return
	}

	filepath.WalkDir(providerDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".psafe3") {
			if os.Remove(path) == nil {
				s.cleanupEmptyParentDirs(filepath.Dir(path), providerDir)
			}
		}
		return nil
	})
}

func (s *SyncableSafesService) cleanupEmptyParentDirs(dir, baseDir string) {
	for dir != baseDir && len(dir) > len(baseDir) {
		if err := os.Remove(dir); err != nil {
			break
		}
		dir = filepath.Dir(dir)
	}
}
