package middleware

import (
	"crypto/subtle"
	"net/http"
)

func RequireCsrfToken(csrfToken string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF token check for OPTIONS preflight
		if r.Method == "OPTIONS" {
			next(w, r)
			return
		}

		// Skip CSRF token check for OAuth callbacks (external redirects)
		if IsOAuthCallback(r.URL.Path) {
			next(w, r)
			return
		}

		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-PWSAFE-CSRF-Token")), []byte(csrfToken)) != 1 {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}
