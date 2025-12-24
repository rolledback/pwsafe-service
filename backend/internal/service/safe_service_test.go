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
		}
		if safe.Name == "three.psafe3" {
			foundThree = true
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

	structure, err := service.UnlockSafe("simple.psafe3", "password")
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

	structure, err := service.UnlockSafe("three.psafe3", "three3#;")
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

	_, err := service.UnlockSafe("simple.psafe3", "wrongpassword")
	if err == nil {
		t.Error("Expected error for wrong password")
	}
}

func TestUnlockSafe_NonexistentFile(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	_, err := service.UnlockSafe("nonexistent.psafe3", "password")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestGetEntryPassword_Simple(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	password, err := service.GetEntryPassword("simple.psafe3", "password", "c4dcfb52-b944-f141-af96-b746f184afe2")
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

	password, err := service.GetEntryPassword("three.psafe3", "three3#;", "6f1738b6-4a22-314a-8bbf-5c3507f0d489")
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

	_, err := service.GetEntryPassword("simple.psafe3", "password", "00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Error("Expected error for nonexistent UUID")
	}
}

func TestGetEntryPassword_WrongPassword(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	_, err := service.GetEntryPassword("simple.psafe3", "wrongpassword", "c4dcfb52-b944-f141-af96-b746f184afe2")
	if err == nil {
		t.Error("Expected error for wrong password")
	}
}

func TestGetEntryPassword_NonexistentFile(t *testing.T) {
	testDir := "../../testdata"
	service := NewSafeService(testDir)

	_, err := service.GetEntryPassword("nonexistent.psafe3", "password", "c4dcfb52-b944-f141-af96-b746f184afe2")
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
}
