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
// Uses EvalSymlinks to resolve symlinks before checking containment.
func validatePathWithinBase(path, base string) (string, error) {
	absPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		// File doesn't exist yet - resolve the parent directory
		// Walk up until we find an existing ancestor, then append remaining components
		absPath, err = resolveWithExistingAncestor(path)
		if err != nil {
			return "", fmt.Errorf("invalid path: %w", err)
		}
	}

	absBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		absBase, err = filepath.Abs(base)
		if err != nil {
			return "", fmt.Errorf("invalid base directory: %w", err)
		}
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

// resolveWithExistingAncestor resolves symlinks on the closest existing ancestor
// and appends the remaining path components. This prevents symlink attacks where
// a symlinked directory component would escape the containment check.
func resolveWithExistingAncestor(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	// Walk up the path to find the closest existing ancestor
	current := absPath
	var remaining []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			// Found existing ancestor - append remaining components
			for i := len(remaining) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, remaining[i])
			}
			return filepath.Clean(resolved), nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			// Reached root without finding existing path
			return absPath, nil
		}
		remaining = append(remaining, filepath.Base(current))
		current = parent
	}
}
