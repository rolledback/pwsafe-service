package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rolledback/pwsafe-service/backend/internal/models"
	"github.com/tkuhlman/gopwsafe/pwsafe"
)

type SafeService struct {
	safesDirectory string
}

func NewSafeService(safesDirectory string) *SafeService {
	return &SafeService{
		safesDirectory: safesDirectory,
	}
}

func (s *SafeService) ListSafes() ([]models.SafeFile, error) {
	safes := []models.SafeFile{}

	// Scan root safes directory (static safes) - non-recursive
	rootSafes, err := s.scanDirectory(s.safesDirectory, "static", false)
	if err != nil {
		return nil, err
	}
	safes = append(safes, rootSafes...)

	// Scan onedrive subdirectory (synced safes) - recursive to preserve OneDrive path structure
	onedriveDir := filepath.Join(s.safesDirectory, "onedrive")
	onedriveSafes, err := s.scanDirectory(onedriveDir, "onedrive", true)
	if err == nil {
		safes = append(safes, onedriveSafes...)
	}
	// Ignore error if onedrive directory doesn't exist

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
			relPath, _ := filepath.Rel(s.safesDirectory, path)
			apiPath := "/" + filepath.ToSlash(filepath.Join(filepath.Base(s.safesDirectory), relPath))

			safes = append(safes, models.SafeFile{
				Name:         d.Name(),
				Path:         apiPath,
				LastModified: info.ModTime(),
				Source:       source,
			})

			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to scan directory: %w", err)
		}
	} else {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to read safes directory: %w", err)
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
			apiPath := "/" + filepath.ToSlash(filepath.Join(filepath.Base(s.safesDirectory), getRelativePath(s.safesDirectory, dir), entry.Name()))

			safes = append(safes, models.SafeFile{
				Name:         entry.Name(),
				Path:         apiPath,
				LastModified: info.ModTime(),
				Source:       source,
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

// ValidateSafePath validates that the given path is within the safes directory
// and returns the absolute filesystem path if valid.
func (s *SafeService) ValidateSafePath(safePath string) (string, error) {
	// safePath should be like "/safes/file.psafe3" or "/safes/onedrive/file.psafe3"
	// Convert to filesystem path relative to safesDirectory

	// Remove leading slash and "safes/" prefix
	cleanPath := strings.TrimPrefix(safePath, "/")
	safesPrefix := filepath.Base(s.safesDirectory) + "/"
	if !strings.HasPrefix(cleanPath, safesPrefix) {
		return "", fmt.Errorf("invalid safe path: must be within safes directory")
	}
	relativePath := strings.TrimPrefix(cleanPath, safesPrefix)

	// Build absolute path
	absPath := filepath.Join(s.safesDirectory, filepath.FromSlash(relativePath))

	// Security: ensure the resolved path is still within safesDirectory
	absPath, err := filepath.Abs(absPath)
	if err != nil {
		return "", fmt.Errorf("invalid safe path: %w", err)
	}

	absSafesDir, err := filepath.Abs(s.safesDirectory)
	if err != nil {
		return "", fmt.Errorf("invalid safes directory: %w", err)
	}

	// Check that the path is within allowed directories
	if !strings.HasPrefix(absPath, absSafesDir+string(filepath.Separator)) && absPath != absSafesDir {
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
