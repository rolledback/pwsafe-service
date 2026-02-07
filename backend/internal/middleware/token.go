package middleware

import (
	"net/http"
	"strings"
)

func RequireToken(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip token check for OPTIONS preflight
		if r.Method == "OPTIONS" {
			next(w, r)
			return
		}

		// Skip token check for OAuth callbacks (external redirects)
		if strings.HasSuffix(r.URL.Path, "/auth/callback") {
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
