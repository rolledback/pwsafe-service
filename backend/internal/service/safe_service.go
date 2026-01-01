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

	entries, err := os.ReadDir(s.safesDirectory)
	if err != nil {
		return nil, fmt.Errorf("failed to read safes directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".psafe3") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		safes = append(safes, models.SafeFile{
			Name:         entry.Name(),
			Path:         filepath.Join(s.safesDirectory, entry.Name()),
			LastModified: info.ModTime(),
		})
	}

	return safes, nil
}

func (s *SafeService) UnlockSafe(filename, password string) (*models.SafeStructure, error) {
	safePath := filepath.Join(s.safesDirectory, filename)

	if _, err := os.Stat(safePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("safe file not found: %s", filename)
	}

	db, err := pwsafe.OpenPWSafeFile(safePath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to unlock safe: %w", err)
	}

	structure := s.buildGroupTree(db)
	return structure, nil
}

func (s *SafeService) GetEntryPassword(filename, password, entryUUID string) (string, error) {
	safePath := filepath.Join(s.safesDirectory, filename)

	if _, err := os.Stat(safePath); os.IsNotExist(err) {
		return "", fmt.Errorf("safe file not found: %s", filename)
	}

	db, err := pwsafe.OpenPWSafeFile(safePath, password)
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
