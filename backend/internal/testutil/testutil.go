package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// SetupTestDataDir creates a temp directory with the expected structure and copies test files.
// Returns the path to the temp directory (data dir root).
func SetupTestDataDir(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	staticDir := filepath.Join(tmpDir, "static")
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		t.Fatalf("Failed to create static dir: %v", err)
	}

	// Copy test files from testdata to static/
	for _, name := range []string{"simple.psafe3", "three.psafe3"} {
		CopyTestFile(t, filepath.Join(TestDataDir(), name), filepath.Join(staticDir, name))
	}
	return tmpDir
}

// SetupEmptyDataDir creates a temp directory with just the static/ subdirectory (no test files).
// Useful for tests that need to create their own file structure.
func SetupEmptyDataDir(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	staticDir := filepath.Join(tmpDir, "static")
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		t.Fatalf("Failed to create static dir: %v", err)
	}
	return tmpDir
}

// TestDataDir returns the path to the testdata directory.
func TestDataDir() string {
	// This assumes the testutil package is at backend/internal/testutil
	// and testdata is at backend/testdata
	return filepath.Join("..", "..", "testdata")
}

// CopyTestFile copies a file from src to dst.
func CopyTestFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		t.Fatalf("Failed to write %s: %v", dst, err)
	}
}
