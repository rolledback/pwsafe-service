package service

import (
	"fmt"
	"path/filepath"
	"strings"
)

// formatUUID formats a 16-byte UUID slice into standard UUID string format
func formatUUID(u []byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// isSafeFile checks if the filename has the .psafe3 extension (case-insensitive)
func isSafeFile(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".psafe3")
}

// validatePathWithinBase validates that the given path resolves within the base directory
// and returns the absolute path if valid. Returns an error if path traversal is detected.
func validatePathWithinBase(path, base string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("invalid base directory: %w", err)
	}

	absPath = filepath.Clean(absPath)
	absBase = filepath.Clean(absBase)

	if absPath == absBase {
		return absPath, nil
	}

	baseWithSep := absBase
	if !strings.HasSuffix(baseWithSep, string(filepath.Separator)) {
		baseWithSep += string(filepath.Separator)
	}

	if !strings.HasPrefix(absPath, baseWithSep) {
		return "", fmt.Errorf("path traversal not allowed")
	}

	return absPath, nil
}
