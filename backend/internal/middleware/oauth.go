package middleware

import "strings"

// IsOAuthCallback returns true if the request path is a provider OAuth callback.
func IsOAuthCallback(path string) bool {
	return strings.HasPrefix(path, "/api/providers/") && strings.HasSuffix(path, "/auth/callback")
}
