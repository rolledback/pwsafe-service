package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rolledback/pwsafe-service/backend/internal/models"
	"github.com/tkuhlman/gopwsafe/pwsafe"
)

// SafeRef holds the provider and path for a safe, used in ID cache lookups
type SafeRef struct {
	Provider string
	Path     string
}

type SafeService struct {
	dataDir    string
	idCache    map[string]SafeRef // id → {provider, path}
	cacheMutex sync.RWMutex
}

func NewSafeService(dataDir string) *SafeService {
	return &SafeService{
		dataDir: dataDir,
		idCache: make(map[string]SafeRef),
	}
}

// ComputeID generates an 8-character hex ID from SHA256 of provider/relativePath
func (s *SafeService) ComputeID(provider, relativePath string) string {
	input := provider + "/" + relativePath
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:4]) // 4 bytes = 8 hex chars
}

// ResolvePath looks up a safe by ID and returns its provider and path
func (s *SafeService) ResolvePath(id string) (SafeRef, error) {
	s.cacheMutex.RLock()
	defer s.cacheMutex.RUnlock()

	ref, exists := s.idCache[id]
	if !exists {
		return SafeRef{}, fmt.Errorf("safe not found: %s", id)
	}
	return ref, nil
}

// RefreshCache rebuilds the ID cache by listing all safes
func (s *SafeService) RefreshCache() error {
	_, err := s.ListSafes()
	return err
}

func (s *SafeService) ListSafes() ([]models.SafeFile, error) {
	safes := []models.SafeFile{}

	// Scan static safes directory (data/static/) - non-recursive
	staticDir := filepath.Join(s.dataDir, "static")
	staticSafes, err := s.scanDirectory(staticDir, "static", false)
	if err == nil {
		safes = append(safes, staticSafes...)
	}

	// Scan all subdirectories as potential provider directories
	// Each subdirectory (except "static") is treated as a provider (e.g., "onedrive", "gdrive")
	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return safes, nil // Return what we have if we can't read subdirs
	}

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		providerID := entry.Name()
		if providerID == "static" {
			continue // Already handled above
		}

		providerDir := filepath.Join(s.dataDir, providerID)
		providerSafes, err := s.scanDirectory(providerDir, providerID, true)
		if err == nil {
			safes = append(safes, providerSafes...)
		}
	}

	// Rebuild the ID cache
	s.cacheMutex.Lock()
	s.idCache = make(map[string]SafeRef)
	for i := range safes {
		safe := &safes[i]
		// Compute relative path for ID
		var relPath string
		if safe.Provider == "static" {
			// Static safes: relPath is just the filename
			relPath = safe.Name
		} else {
			// Provider safes: extract path relative to provider dir
			relPath = strings.TrimPrefix(safe.Path, "/data/"+safe.Provider+"/")
		}
		id := s.ComputeID(safe.Provider, relPath)
		safe.ID = id
		s.idCache[id] = SafeRef{Provider: safe.Provider, Path: safe.Path}
	}
	s.cacheMutex.Unlock()

	return safes, nil
}

func (s *SafeService) scanDirectory(dir, source string, recursive bool) ([]models.SafeFile, error) {
	safes := []models.SafeFile{}

	if recursive {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			// Skip hidden files and directories
			if strings.HasPrefix(d.Name(), ".") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if d.IsDir() {
				return nil
			}

			if !strings.HasSuffix(strings.ToLower(d.Name()), ".psafe3") {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}

			// Use forward slashes for API path consistency (URL-style)
			relPath, _ := filepath.Rel(s.dataDir, path)
			apiPath := "/data/" + filepath.ToSlash(relPath)

			safes = append(safes, models.SafeFile{
				Name:         d.Name(),
				Path:         apiPath,
				LastModified: info.ModTime(),
				Provider:     source,
			})

			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to scan directory: %w", err)
		}
	} else {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory: %w", err)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			// Skip hidden files
			if strings.HasPrefix(entry.Name(), ".") {
				continue
			}

			if !strings.HasSuffix(strings.ToLower(entry.Name()), ".psafe3") {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Use forward slashes for API path consistency (URL-style)
			relPath, _ := filepath.Rel(s.dataDir, filepath.Join(dir, entry.Name()))
			apiPath := "/data/" + filepath.ToSlash(relPath)

			safes = append(safes, models.SafeFile{
				Name:         entry.Name(),
				Path:         apiPath,
				LastModified: info.ModTime(),
				Provider:     source,
			})
		}
	}

	return safes, nil
}

func getRelativePath(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == "." {
		return ""
	}
	return rel
}

// ValidateSafePath validates that the given path is within the data directory
// and returns the absolute filesystem path if valid.
func (s *SafeService) ValidateSafePath(safePath string) (string, error) {
	// safePath should be like "/data/static/file.psafe3" or "/data/onedrive/file.psafe3"
	// Convert to filesystem path relative to dataDir

	// Remove leading slash and "data/" prefix
	cleanPath := strings.TrimPrefix(safePath, "/")
	if !strings.HasPrefix(cleanPath, "data/") {
		return "", fmt.Errorf("invalid safe path: must be within data directory")
	}
	relativePath := strings.TrimPrefix(cleanPath, "data/")

	// Build absolute path
	absPath := filepath.Join(s.dataDir, filepath.FromSlash(relativePath))

	// Security: ensure the resolved path is still within dataDir
	absPath, err := filepath.Abs(absPath)
	if err != nil {
		return "", fmt.Errorf("invalid safe path: %w", err)
	}

	absDataDir, err := filepath.Abs(s.dataDir)
	if err != nil {
		return "", fmt.Errorf("invalid data directory: %w", err)
	}

	// Check that the path is within allowed directories
	if !strings.HasPrefix(absPath, absDataDir+string(filepath.Separator)) && absPath != absDataDir {
		return "", fmt.Errorf("invalid safe path: directory traversal not allowed")
	}

	// Check file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return "", fmt.Errorf("safe file not found: %s", safePath)
	}

	return absPath, nil
}

func (s *SafeService) UnlockSafe(safePath, password string) (*models.SafeStructure, error) {
	absPath, err := s.ValidateSafePath(safePath)
	if err != nil {
		return nil, err
	}

	db, err := pwsafe.OpenPWSafeFile(absPath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to unlock safe: %w", err)
	}

	structure := s.buildGroupTree(db)
	return structure, nil
}

func (s *SafeService) GetEntryPassword(safePath, password, entryUUID string) (string, error) {
	absPath, err := s.ValidateSafePath(safePath)
	if err != nil {
		return "", err
	}

	db, err := pwsafe.OpenPWSafeFile(absPath, password)
	if err != nil {
		return "", fmt.Errorf("failed to unlock safe: %w", err)
	}

	for _, record := range db.Records {
		uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
			record.UUID[0:4],
			record.UUID[4:6],
			record.UUID[6:8],
			record.UUID[8:10],
			record.UUID[10:16])

		if uuid == entryUUID {
			return record.Password, nil
		}
	}

	return "", fmt.Errorf("entry not found: %s", entryUUID)
}

func (s *SafeService) buildGroupTree(db *pwsafe.V3) *models.SafeStructure {
	groupMap := make(map[string]*models.Group)
	rootGroups := make(map[string]*models.Group)
	rootEntries := []models.Entry{}

	for _, record := range db.Records {
		groupPath := record.Group
		title := record.Title
		uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
			record.UUID[0:4],
			record.UUID[4:6],
			record.UUID[6:8],
			record.UUID[8:10],
			record.UUID[10:16])
		username := record.Username
		url := record.URL
		notes := record.Notes

		entry := models.Entry{
			UUID:     uuid,
			Title:    title,
			Username: username,
			URL:      url,
			Notes:    notes,
		}

		if groupPath == "" {
			rootEntries = append(rootEntries, entry)
			continue
		}

		parts := strings.Split(groupPath, ".")
		var currentPath string
		var parentGroup *models.Group

		for i, part := range parts {
			if currentPath == "" {
				currentPath = part
			} else {
				currentPath = currentPath + "." + part
			}

			group, exists := groupMap[currentPath]
			if !exists {
				group = &models.Group{
					Name:    part,
					Groups:  []*models.Group{},
					Entries: []models.Entry{},
				}
				groupMap[currentPath] = group

				if i == 0 {
					rootGroups[currentPath] = group
				} else if parentGroup != nil {
					parentGroup.Groups = append(parentGroup.Groups, group)
				}
			}

			parentGroup = group
		}

		if parentGroup != nil {
			parentGroup.Entries = append(parentGroup.Entries, entry)
		}
	}

	var groups []*models.Group
	for _, group := range rootGroups {
		groups = append(groups, group)
	}

	return &models.SafeStructure{
		Groups:  groups,
		Entries: rootEntries,
	}
}
