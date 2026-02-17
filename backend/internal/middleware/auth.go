package middleware

import (
	"net/http"

	"github.com/rolledback/pwsafe-service/backend/internal/auth"
)

// RequireAuth middleware checks authentication based on the current mode
func RequireAuth(authService *auth.AuthService, trustedProxies []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mode := authService.GetMode()
		switch mode {
		case "unset":
			http.Error(w, "Service not configured", http.StatusServiceUnavailable)
			return
		case "disabled":
			next(w, r)
			return
		case "enabled":
			// Skip auth for OPTIONS preflight
			if r.Method == "OPTIONS" {
				next(w, r)
				return
			}

			ip := GetClientIP(r, trustedProxies)
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
