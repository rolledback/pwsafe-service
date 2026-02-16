package service

import (
	"path/filepath"
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
