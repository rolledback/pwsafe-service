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
	dataDir         string
	maxSafeFileSize int64
	provider        provider.SyncableSafesProvider

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
	dataDir string,
	p provider.SyncableSafesProvider,
	syncInterval time.Duration,
	maxSafeFileSize int64,
) *SyncableSafesService {
	if syncInterval <= 0 {
		syncInterval = defaultSyncInterval
	}
	ctx, cancel := context.WithCancel(ctx)
	svc := &SyncableSafesService{
		dataDir:         dataDir,
		maxSafeFileSize: maxSafeFileSize,
		provider:        p,
		syncInterval:    syncInterval,
		nextSyncAt:      time.Now().Add(syncInterval),
		ctx:             ctx,
		cancel:          cancel,
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

// logIDFromEmail formats a "providerID (accountEmail)" string for log lines,
// falling back to just the provider ID if email is empty.
func (s *SyncableSafesService) logIDFromEmail(accountEmail string) string {
	if accountEmail == "" {
		return s.provider.ID()
	}
	return fmt.Sprintf("%s (%s)", s.provider.ID(), accountEmail)
}

// logID returns a "providerID (accountEmail)" string for log lines, using only
// locally-cached connection info (no network calls, attemptRefresh=false).
func (s *SyncableSafesService) logID(ctx context.Context) string {
	status, err := s.provider.GetConnectionStatus(ctx, false)
	if err != nil {
		return s.provider.ID()
	}
	return s.logIDFromEmail(status.AccountEmail)
}

// GetProviderStatus returns the provider status merged with sync timing
func (s *SyncableSafesService) GetProviderStatus(ctx context.Context) (*ProviderStatus, error) {
	s.syncMutex.RLock()
	defer s.syncMutex.RUnlock()

	status, err := s.provider.GetConnectionStatus(ctx, true) // attemptRefresh=true for accurate status
	if err != nil {
		return nil, err
	}

	config := s.loadConfigOrEmpty("GetProviderStatus")

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

// ListFiles returns remote files merged with saved selection state. Files whose
// id changed since last save (matched by path+name) carry their selection
// forward instead of appearing unselected.
func (s *SyncableSafesService) ListFiles(ctx context.Context) ([]SelectedFile, error) {
	// Load saved config
	config := s.loadConfigOrEmpty("ListFiles")
	savedByID := make(map[string]SelectedFile, len(config.Files))
	savedByPathName := make(map[string]SelectedFile, len(config.Files))
	for _, f := range config.Files {
		savedByID[f.ID] = f
		savedByPathName[f.Path+"\x00"+f.Name] = f
	}

	// Fetch remote files
	remoteFiles, err := s.provider.ListRemoteFiles(ctx)
	if err != nil {
		// Return cached files if remote unavailable
		log.Printf("%s: ListFiles: remote fetch failed, returning %d cached file(s): %v", s.logID(ctx), len(config.Files), err)
		return config.Files, nil
	}

	// Merge: remote files + saved selection state, falling back to path+name
	// matching when the id itself doesn't match anything saved.
	var result []SelectedFile
	selectedCount := 0
	seenIDs := make(map[string]bool, len(remoteFiles))
	idMigrations := make(map[string]string) // old id -> new id
	for _, rf := range remoteFiles {
		seenIDs[rf.ID] = true

		saved, ok := savedByID[rf.ID]
		if !ok {
			if byPathName, ok2 := savedByPathName[rf.Path+"\x00"+rf.Name]; ok2 && byPathName.ID != rf.ID {
				log.Printf("%s: ListFiles: file %q changed id (%s -> %s), carrying forward its selection", s.logID(ctx), rf.Name, byPathName.ID, rf.ID)
				saved = byPathName
				idMigrations[byPathName.ID] = rf.ID
			}
		}

		if saved.Selected {
			selectedCount++
		}
		result = append(result, SelectedFile{
			ID:       rf.ID,
			Name:     rf.Name,
			Path:     rf.Path,
			Size:     rf.Size,
			Selected: saved.Selected,
		})
	}

	// Warn about previously-selected files this listing didn't return at all,
	// excluding ones already accounted for by an id migration above.
	for _, f := range config.Files {
		if !f.Selected || seenIDs[f.ID] {
			continue
		}
		if _, migratedAway := idMigrations[f.ID]; migratedAway {
			continue
		}
		log.Printf("%s: ListFiles: WARNING previously-selected file %q (id=%s) is absent from this listing of %d file(s)", s.logID(ctx), f.Name, f.ID, len(remoteFiles))
	}

	log.Printf("%s: ListFiles: remote fetch returned %d file(s), %d currently selected", s.logID(ctx), len(remoteFiles), selectedCount)

	// Persist id migrations so periodic Sync, which reads the saved config
	// directly, uses the new id right away.
	if len(idMigrations) > 0 {
		updated := make([]SelectedFile, len(config.Files))
		copy(updated, config.Files)
		for i, f := range updated {
			if newID, ok := idMigrations[f.ID]; ok {
				updated[i].ID = newID
			}
		}
		config.Files = updated
		if err := s.saveConfig(config); err != nil {
			log.Printf("%s: ListFiles: failed to persist migrated file id(s): %v", s.logID(ctx), err)
		}
	}

	return result, nil
}

// SaveFiles persists file selection state after validating paths
func (s *SyncableSafesService) SaveFiles(files []SelectedFile) error {
	for _, f := range files {
		if _, err := s.getLocalPath(f); err != nil {
			return fmt.Errorf("invalid file path: %w", err)
		}
	}

	var selectedNames []string
	for _, f := range files {
		if f.Selected {
			selectedNames = append(selectedNames, f.Name)
		}
	}
	log.Printf("%s: SaveFiles: saving selection for %d file(s), %d selected: %v", s.logID(context.Background()), len(files), len(selectedNames), selectedNames)

	config := s.loadConfigOrEmpty("SaveFiles")
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

	logID := s.logIDFromEmail(status.AccountEmail)

	log.Printf("%s: Sync: starting, %d file(s) selected", logID, len(selectedFiles))

	var results []SyncResult

	// Step 2: For each selected file, download from remote
	for _, file := range selectedFiles {
		// Skip oversized files
		if file.Size > 0 && file.Size > s.maxSafeFileSize {
			log.Printf("%s: skipping oversized file %q (%d bytes > %d max)", s.provider.ID(), file.Name, file.Size, s.maxSafeFileSize)
			results = append(results, SyncResult{Name: file.Name, Success: false, Error: fmt.Sprintf("file exceeds maximum size (%d bytes)", s.maxSafeFileSize)})
			continue
		}

		localPath, err := s.getLocalPath(file)
		if err != nil {
			log.Printf("%s: skipping file %q: %v", s.provider.ID(), file.Name, err)
			results = append(results, SyncResult{Name: file.Name, Success: false, Error: err.Error()})
			continue
		}
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
			log.Printf("%s: Sync: failed to download %q: %v", s.provider.ID(), file.Name, err)
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

	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}
	log.Printf("%s: Sync: completed (%d/%d file(s) downloaded successfully)", logID, successCount, len(results))

	return results, nil
}

// Disconnect removes provider connection and cleans up
func (s *SyncableSafesService) Disconnect(ctx context.Context) error {
	// Capture the log label before the provider clears its tokens - after
	// Disconnect() below, the account email is no longer available to read.
	logID := s.logID(ctx)

	// Let provider clean up its auth state (tokens)
	if err := s.provider.Disconnect(ctx); err != nil {
		return err
	}

	// Clean up generic state (config + synced files)
	os.Remove(s.configPath())
	s.cleanupAllSafeFiles()

	log.Printf("%s: Disconnect: removed saved selection and synced files", logID)

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
	if err != nil {
		log.Printf("%s: periodic sync skipped: failed to check connection status: %v", s.provider.ID(), err)
		return
	}
	if !status.Connected {
		reason := "not connected"
		if status.NeedsReauth {
			reason = "needs reauth"
		}
		log.Printf("%s: periodic sync skipped: %s", s.provider.ID(), reason)
		return
	}

	if _, err := s.Sync(s.ctx); err != nil {
		log.Printf("%s: periodic sync failed: %v", s.provider.ID(), err)
	}
}

func (s *SyncableSafesService) providerDir() string {
	return filepath.Join(s.dataDir, s.provider.ID())
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

// loadConfigOrEmpty loads the saved config, logging (rather than silently discarding)
// any error reading/parsing it, and falling back to an empty config so callers never
// have to handle a nil result.
func (s *SyncableSafesService) loadConfigOrEmpty(caller string) *SyncConfig {
	config, err := s.loadConfig()
	if err != nil {
		log.Printf("%s: %s: failed to load saved config, treating as empty: %v", s.provider.ID(), caller, err)
		return &SyncConfig{Files: []SelectedFile{}}
	}
	return config
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

func (s *SyncableSafesService) getLocalPath(file SelectedFile) (string, error) {
	relativePath := filepath.FromSlash(file.Path)
	relativePath = strings.TrimPrefix(relativePath, string(filepath.Separator))
	joined := filepath.Clean(filepath.Join(s.providerDir(), relativePath, file.Name))

	absPath, err := validatePathWithinBase(joined, s.providerDir())
	if err != nil {
		return "", fmt.Errorf("path traversal not allowed: %s", file.Path)
	}

	return absPath, nil
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

	// Enforce size limit regardless of what the provider reported
	limited := io.LimitReader(result.Content, s.maxSafeFileSize+1)
	written, err := io.Copy(file, limited)
	if err != nil {
		file.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to write file: %w", err)
	}
	file.Close()

	if written > s.maxSafeFileSize {
		os.Remove(tmpPath)
		return "", fmt.Errorf("downloaded file exceeds maximum size (%d bytes)", s.maxSafeFileSize)
	}

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
		p, err := s.getLocalPath(f)
		if err != nil {
			continue
		}
		selectedPaths[p] = true
	}

	providerDir := s.providerDir()
	filepath.WalkDir(providerDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		if isSafeFile(d.Name()) {
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
		if isSafeFile(d.Name()) {
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
