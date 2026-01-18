package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListSafes(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	safes, err := service.ListSafes()
	if err != nil {
		t.Fatalf("ListSafes failed: %v", err)
	}

	if len(safes) < 2 {
		t.Errorf("Expected at least 2 safe files, got %d", len(safes))
	}

	foundSimple := false
	foundThree := false
	for _, safe := range safes {
		if safe.Name == "simple.psafe3" {
			foundSimple = true
			if safe.Source != "static" {
				t.Errorf("Expected source 'static' for simple.psafe3, got '%s'", safe.Source)
			}
			if safe.Path != "/testdata/simple.psafe3" {
				t.Errorf("Expected path '/testdata/simple.psafe3', got '%s'", safe.Path)
			}
		}
		if safe.Name == "three.psafe3" {
			foundThree = true
			if safe.Source != "static" {
				t.Errorf("Expected source 'static' for three.psafe3, got '%s'", safe.Source)
			}
		}
	}

	if !foundSimple {
		t.Error("Expected to find simple.psafe3")
	}
	if !foundThree {
		t.Error("Expected to find three.psafe3")
	}
}

func TestListSafes_NonexistentDirectory(t *testing.T) {
	service := NewSafeService("/nonexistent/path")

	_, err := service.ListSafes()
	if err == nil {
		t.Error("Expected error for nonexistent directory")
	}
}

func TestUnlockSafe_Simple(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	structure, err := service.UnlockSafe("/testdata/simple.psafe3", "password")
	if err != nil {
		t.Fatalf("UnlockSafe failed: %v", err)
	}

	if len(structure.Groups) != 1 {
		t.Errorf("Expected 1 group, got %d", len(structure.Groups))
	}

	if structure.Groups[0].Name != "test" {
		t.Errorf("Expected group name 'test', got '%s'", structure.Groups[0].Name)
	}

	if len(structure.Groups[0].Entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(structure.Groups[0].Entries))
	}

	entry := structure.Groups[0].Entries[0]
	if entry.Title != "Test entry" {
		t.Errorf("Expected title 'Test entry', got '%s'", entry.Title)
	}
	if entry.Username != "test" {
		t.Errorf("Expected username 'test', got '%s'", entry.Username)
	}
	if entry.UUID != "c4dcfb52-b944-f141-af96-b746f184afe2" {
		t.Errorf("Expected UUID 'c4dcfb52-b944-f141-af96-b746f184afe2', got '%s'", entry.UUID)
	}
}

func TestUnlockSafe_Three(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	structure, err := service.UnlockSafe("/testdata/three.psafe3", "three3#;")
	if err != nil {
		t.Fatalf("UnlockSafe failed: %v", err)
	}

	if len(structure.Groups) != 3 {
		t.Errorf("Expected 3 groups, got %d", len(structure.Groups))
	}
}

func TestUnlockSafe_WrongPassword(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	_, err := service.UnlockSafe("/testdata/simple.psafe3", "wrongpassword")
	if err == nil {
		t.Error("Expected error for wrong password")
	}
}

func TestUnlockSafe_NonexistentFile(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	_, err := service.UnlockSafe("/testdata/nonexistent.psafe3", "password")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestUnlockSafe_DirectoryTraversal(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	_, err := service.UnlockSafe("/testdata/../../../etc/passwd", "password")
	if err == nil {
		t.Error("Expected error for directory traversal attempt")
	}
}

func TestUnlockSafe_InvalidPath(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	_, err := service.UnlockSafe("/other/simple.psafe3", "password")
	if err == nil {
		t.Error("Expected error for invalid path prefix")
	}
}

func TestGetEntryPassword_Simple(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	password, err := service.GetEntryPassword("/testdata/simple.psafe3", "password", "c4dcfb52-b944-f141-af96-b746f184afe2")
	if err != nil {
		t.Fatalf("GetEntryPassword failed: %v", err)
	}

	if password != "password" {
		t.Errorf("Expected password 'password', got '%s'", password)
	}
}

func TestGetEntryPassword_Three(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	password, err := service.GetEntryPassword("/testdata/three.psafe3", "three3#;", "6f1738b6-4a22-314a-8bbf-5c3507f0d489")
	if err != nil {
		t.Fatalf("GetEntryPassword failed: %v", err)
	}

	if password != "three1!@$%^&*()" {
		t.Errorf("Expected password 'three1!@$%%^&*()', got '%s'", password)
	}
}

func TestGetEntryPassword_WrongUUID(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	_, err := service.GetEntryPassword("/testdata/simple.psafe3", "password", "00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Error("Expected error for nonexistent UUID")
	}
}

func TestGetEntryPassword_WrongPassword(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	_, err := service.GetEntryPassword("/testdata/simple.psafe3", "wrongpassword", "c4dcfb52-b944-f141-af96-b746f184afe2")
	if err == nil {
		t.Error("Expected error for wrong password")
	}
}

func TestGetEntryPassword_NonexistentFile(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	_, err := service.GetEntryPassword("/testdata/nonexistent.psafe3", "password", "c4dcfb52-b944-f141-af96-b746f184afe2")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestListSafes_OnlyPsafe3Files(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "test.psafe3"), []byte{}, 0644)
	os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte{}, 0644)
	os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte{}, 0644)
	os.Mkdir(filepath.Join(tmpDir, "subdir"), 0755)

	service := NewSafeService(tmpDir)
	safes, err := service.ListSafes()
	if err != nil {
		t.Fatalf("ListSafes failed: %v", err)
	}

	if len(safes) != 1 {
		t.Errorf("Expected 1 safe file, got %d", len(safes))
	}

	if safes[0].Name != "test.psafe3" {
		t.Errorf("Expected 'test.psafe3', got '%s'", safes[0].Name)
	}

	if safes[0].Source != "static" {
		t.Errorf("Expected source 'static', got '%s'", safes[0].Source)
	}
}

func TestListSafes_WithOnedriveSubdir(t *testing.T) {
	tmpDir := t.TempDir()
	baseName := filepath.Base(tmpDir)

	// Create static safe
	os.WriteFile(filepath.Join(tmpDir, "static.psafe3"), []byte{}, 0644)

	// Create onedrive subdir with nested directories preserving OneDrive path structure
	onedriveDir := filepath.Join(tmpDir, "onedrive")
	os.MkdirAll(filepath.Join(onedriveDir, "Documents", "Passwords"), 0755)
	os.WriteFile(filepath.Join(onedriveDir, "synced.psafe3"), []byte{}, 0644)
	os.WriteFile(filepath.Join(onedriveDir, "Documents", "Passwords", "work.psafe3"), []byte{}, 0644)

	// Create hidden files that should be skipped
	os.WriteFile(filepath.Join(onedriveDir, ".tokens.json"), []byte{}, 0644)
	os.WriteFile(filepath.Join(onedriveDir, ".config.json"), []byte{}, 0644)

	service := NewSafeService(tmpDir)
	safes, err := service.ListSafes()
	if err != nil {
		t.Fatalf("ListSafes failed: %v", err)
	}

	if len(safes) != 3 {
		t.Errorf("Expected 3 safe files, got %d", len(safes))
		for _, s := range safes {
			t.Logf("  Found: %s (path: %s)", s.Name, s.Path)
		}
	}

	foundStatic := false
	foundSynced := false
	foundWork := false
	for _, safe := range safes {
		if safe.Name == "static.psafe3" {
			foundStatic = true
			if safe.Source != "static" {
				t.Errorf("Expected source 'static', got '%s'", safe.Source)
			}
		}
		if safe.Name == "synced.psafe3" {
			foundSynced = true
			if safe.Source != "onedrive" {
				t.Errorf("Expected source 'onedrive', got '%s'", safe.Source)
			}
			expectedPath := "/" + baseName + "/onedrive/synced.psafe3"
			if safe.Path != expectedPath {
				t.Errorf("Expected path '%s', got '%s'", expectedPath, safe.Path)
			}
		}
		if safe.Name == "work.psafe3" {
			foundWork = true
			if safe.Source != "onedrive" {
				t.Errorf("Expected source 'onedrive', got '%s'", safe.Source)
			}
			expectedPath := "/" + baseName + "/onedrive/Documents/Passwords/work.psafe3"
			if safe.Path != expectedPath {
				t.Errorf("Expected path '%s', got '%s'", expectedPath, safe.Path)
			}
		}
	}

	if !foundStatic {
		t.Error("Expected to find static.psafe3")
	}
	if !foundSynced {
		t.Error("Expected to find synced.psafe3 from onedrive")
	}
	if !foundWork {
		t.Error("Expected to find work.psafe3 from nested onedrive directory")
	}
}

func TestListSafes_NoOnedriveSubdir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create static safe only, no onedrive dir
	os.WriteFile(filepath.Join(tmpDir, "static.psafe3"), []byte{}, 0644)

	service := NewSafeService(tmpDir)
	safes, err := service.ListSafes()
	if err != nil {
		t.Fatalf("ListSafes failed: %v", err)
	}

	if len(safes) != 1 {
		t.Errorf("Expected 1 safe file, got %d", len(safes))
	}
}

func TestListSafes_OnedriveDeepNesting(t *testing.T) {
	tmpDir := t.TempDir()
	baseName := filepath.Base(tmpDir)

	// Create deeply nested OneDrive structure
	onedriveDir := filepath.Join(tmpDir, "onedrive")
	deepPath := filepath.Join(onedriveDir, "Personal", "Finance", "Banking", "Accounts")
	os.MkdirAll(deepPath, 0755)
	os.WriteFile(filepath.Join(deepPath, "bank.psafe3"), []byte{}, 0644)

	service := NewSafeService(tmpDir)
	safes, err := service.ListSafes()
	if err != nil {
		t.Fatalf("ListSafes failed: %v", err)
	}

	if len(safes) != 1 {
		t.Errorf("Expected 1 safe file, got %d", len(safes))
	}

	if safes[0].Name != "bank.psafe3" {
		t.Errorf("Expected name 'bank.psafe3', got '%s'", safes[0].Name)
	}

	expectedPath := "/" + baseName + "/onedrive/Personal/Finance/Banking/Accounts/bank.psafe3"
	if safes[0].Path != expectedPath {
		t.Errorf("Expected path '%s', got '%s'", expectedPath, safes[0].Path)
	}
}

func TestListSafes_SkipsHiddenFilesInRoot(t *testing.T) {
	tmpDir := t.TempDir()

	// Create normal safe and hidden files in root
	os.WriteFile(filepath.Join(tmpDir, "normal.psafe3"), []byte{}, 0644)
	os.WriteFile(filepath.Join(tmpDir, ".hidden.psafe3"), []byte{}, 0644)
	os.WriteFile(filepath.Join(tmpDir, ".tokens.json"), []byte{}, 0644)

	service := NewSafeService(tmpDir)
	safes, err := service.ListSafes()
	if err != nil {
		t.Fatalf("ListSafes failed: %v", err)
	}

	if len(safes) != 1 {
		t.Errorf("Expected 1 safe file (hidden files skipped), got %d", len(safes))
	}

	if safes[0].Name != "normal.psafe3" {
		t.Errorf("Expected name 'normal.psafe3', got '%s'", safes[0].Name)
	}
}

func TestListSafes_SkipsHiddenDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	// Create onedrive with hidden directory containing a safe
	onedriveDir := filepath.Join(tmpDir, "onedrive")
	hiddenDir := filepath.Join(onedriveDir, ".hidden")
	os.MkdirAll(hiddenDir, 0755)
	os.WriteFile(filepath.Join(hiddenDir, "secret.psafe3"), []byte{}, 0644)

	// Also create a visible safe
	os.WriteFile(filepath.Join(onedriveDir, "visible.psafe3"), []byte{}, 0644)

	service := NewSafeService(tmpDir)
	safes, err := service.ListSafes()
	if err != nil {
		t.Fatalf("ListSafes failed: %v", err)
	}

	if len(safes) != 1 {
		t.Errorf("Expected 1 safe file (hidden directory skipped), got %d", len(safes))
		for _, s := range safes {
			t.Logf("  Found: %s", s.Name)
		}
	}

	if len(safes) > 0 && safes[0].Name != "visible.psafe3" {
		t.Errorf("Expected name 'visible.psafe3', got '%s'", safes[0].Name)
	}
}
