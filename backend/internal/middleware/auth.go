package middleware

import (
	"net/http"

	"github.com/rolledback/pwsafe-service/backend/internal/auth"
)

// RequireAuth middleware checks authentication based on the current mode
func RequireAuth(authService *auth.AuthService, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check IP ban first
		ip := GetClientIP(r)
		if authService.IsIPBanned(ip) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		mode := authService.GetMode()
		switch mode {
		case "unset":
			http.Error(w, "Service not configured", http.StatusServiceUnavailable)
			return
		case "unsecured":
			next(w, r)
			return
		case "secured":
			// Skip auth for OPTIONS preflight
			if r.Method == "OPTIONS" {
				next(w, r)
				return
			}

			sessionID := auth.GetSessionIDFromRequest(r)
			if sessionID == "" || !authService.ValidateSession(sessionID, ip) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		default:
			http.Error(w, "Service not configured", http.StatusServiceUnavailable)
		}
	}
}
