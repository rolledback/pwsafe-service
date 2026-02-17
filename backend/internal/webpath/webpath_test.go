package webpath

import (
	"runtime"
	"testing"
)

func TestIsValid(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		valid bool
	}{
		{"normal path", "/css/style.css", true},
		{"root", "/", true},
		{"index", "/index.html", true},
		{"null byte", "/foo\x00bar", false},
		{"tab", "/foo\tbar", false},
		{"newline", "/foo\nbar", false},
		{"carriage return", "/foo\rbar", false},
		{"DEL char", "/foo\x7fbar", false},
		{"control char 0x01", "/foo\x01bar", false},
	}

	// Windows-specific tests
	if runtime.GOOS == "windows" {
		tests = append(tests, []struct {
			name  string
			path  string
			valid bool
		}{
			{"pipe char", "/foo|bar", false},
			{"question mark", "/foo?bar", false},
			{"asterisk", "/foo*bar", false},
			{"angle brackets", "/foo<bar>", false},
			{"colon", "/foo:bar", false},
			{"double quote", `/foo"bar`, false},
		}...)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsValid(tc.path)
			if got != tc.valid {
				t.Errorf("IsValid(%q) = %v, want %v", tc.path, got, tc.valid)
			}
		})
	}
}
