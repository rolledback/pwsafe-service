package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePathWithinBase_ValidSubpath(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "subdir", "file.txt")
	absPath, err := validatePathWithinBase(path, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected, _ := filepath.Abs(path)
	if absPath != expected {
		t.Errorf("expected %q, got %q", expected, absPath)
	}
}

func TestValidatePathWithinBase_PathEqualsBase(t *testing.T) {
	base := t.TempDir()
	absPath, err := validatePathWithinBase(base, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected, _ := filepath.Abs(base)
	if absPath != expected {
		t.Errorf("expected %q, got %q", expected, absPath)
	}
}

func TestValidatePathWithinBase_TraversalBlocked(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "..", "etc", "passwd")
	_, err := validatePathWithinBase(path, base)
	if err == nil {
		t.Fatal("expected error for path traversal, got nil")
	}
}

func TestValidatePathWithinBase_SiblingDirBlocked(t *testing.T) {
	// A sibling directory whose name starts with the base name
	// e.g., base="/tmp/data", path="/tmp/data-evil/file.txt"
	base := t.TempDir()
	sibling := base + "-evil"
	path := filepath.Join(sibling, "file.txt")
	_, err := validatePathWithinBase(path, base)
	if err == nil {
		t.Fatal("expected error for sibling directory, got nil")
	}
}

func TestValidatePathWithinBase_BaseWithTrailingSep(t *testing.T) {
	base := t.TempDir()
	baseWithSep := base + string(filepath.Separator)
	path := filepath.Join(base, "file.txt")
	absPath, err := validatePathWithinBase(path, baseWithSep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected, _ := filepath.Abs(path)
	if absPath != expected {
		t.Errorf("expected %q, got %q", expected, absPath)
	}
}

func TestFormatUUID(t *testing.T) {
	uuid := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	result := formatUUID(uuid)
	expected := "01234567-89ab-cdef-0123-456789abcdef"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestValidatePathWithinBase_SymlinkOutsideBaseRejected(t *testing.T) {
	// Create symlink pointing outside base dir
	base := t.TempDir()
	outside := t.TempDir()

	// Create a file outside base
	outsideFile := filepath.Join(outside, "secret.txt")
	os.WriteFile(outsideFile, []byte("secret"), 0644)

	// Create symlink inside base pointing to outside file
	symlink := filepath.Join(base, "link.txt")
	err := os.Symlink(outsideFile, symlink)
	if err != nil {
		t.Skip("cannot create symlinks (may require admin on Windows)")
	}

	_, err = validatePathWithinBase(symlink, base)
	if err == nil {
		t.Fatal("expected error for symlink pointing outside base, got nil")
	}
}

func TestValidatePathWithinBase_NormalPathWithinBaseAccepted(t *testing.T) {
	base := t.TempDir()
	subdir := filepath.Join(base, "sub")
	os.MkdirAll(subdir, 0755)
	file := filepath.Join(subdir, "file.txt")
	os.WriteFile(file, []byte("data"), 0644)

	absPath, err := validatePathWithinBase(file, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should resolve to a path within base
	resolved, _ := filepath.EvalSymlinks(base)
	if !strings.HasPrefix(absPath, resolved) {
		t.Errorf("expected path %q to be within base %q", absPath, resolved)
	}
}

func TestValidatePathWithinBase_BaseWithSymlinkComponent(t *testing.T) {
	root := t.TempDir()
	realBase := filepath.Join(root, "realdir")
	os.MkdirAll(realBase, 0755)

	// Create a file inside the real base
	file := filepath.Join(realBase, "file.txt")
	os.WriteFile(file, []byte("data"), 0644)

	// Create a symlink to realBase
	symlinkBase := filepath.Join(root, "linkdir")
	err := os.Symlink(realBase, symlinkBase)
	if err != nil {
		t.Skip("cannot create symlinks (may require admin on Windows)")
	}

	// Use the symlink-based path for both path and base
	symlinkFile := filepath.Join(symlinkBase, "file.txt")
	absPath, err := validatePathWithinBase(symlinkFile, symlinkBase)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if absPath == "" {
		t.Fatal("expected non-empty resolved path")
	}
}

func TestValidatePathWithinBase_SymlinkDirEscapeRejected(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()

	// Create subdirectory inside base
	sub := filepath.Join(base, "sub")
	os.MkdirAll(sub, 0755)

	// Create a symlink sub/link -> outside directory
	link := filepath.Join(sub, "link")
	err := os.Symlink(outside, link)
	if err != nil {
		t.Skip("cannot create symlinks (may require admin on Windows)")
	}

	// A non-existent file through the symlink should be rejected
	path := filepath.Join(sub, "link", "newfile.txt")
	_, err = validatePathWithinBase(path, base)
	if err == nil {
		t.Fatal("expected error for path through symlink escaping base, got nil")
	}
}

func TestIsSafeFile(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"test.psafe3", true},
		{"TEST.PSAFE3", true},
		{"test.Psafe3", true},
		{"test.txt", false},
		{"psafe3", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isSafeFile(tc.name); got != tc.want {
			t.Errorf("isSafeFile(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
