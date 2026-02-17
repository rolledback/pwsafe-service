package webpath

import "runtime"

// IsValid returns true if the path contains no control characters
// and (on Windows) no Windows-reserved characters.
func IsValid(path string) bool {
	for _, c := range path {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	if runtime.GOOS == "windows" {
		for _, c := range path {
			switch c {
			case '<', '>', ':', '"', '|', '?', '*':
				return false
			}
		}
	}
	return true
}
