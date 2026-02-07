package middleware

import (
	"net/http"
	"strings"
)

// IsOAuthCallback returns true if the request path is a provider OAuth callback.
func IsOAuthCallback(path string) bool {
	return strings.HasPrefix(path, "/api/providers/") && strings.HasSuffix(path, "/auth/callback")
}

func RequireToken(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip token check for OPTIONS preflight
		if r.Method == "OPTIONS" {
			next(w, r)
			return
		}

		// Skip token check for OAuth callbacks (external redirects)
		if IsOAuthCallback(r.URL.Path) {
			next(w, r)
			return
		}

		if r.Header.Get("X-PWSAFE-Token") != token {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}
