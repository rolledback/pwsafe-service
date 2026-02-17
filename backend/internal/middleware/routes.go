package middleware

import (
	"net/http"

	"github.com/rolledback/pwsafe-service/backend/internal/auth"
)

// Route describes an API endpoint and which middleware layers to apply.
type Route struct {
	Pattern string
	Handler http.HandlerFunc
	Method  string       // if set, reject requests with wrong method (405)
	Auth    bool         // wrap with RequireAuth
	Csrf    bool         // wrap with RequireCsrfToken
	Limiter *RateLimiter // wrap with Limit (nil = no rate limit)
}

// RegisterRoutes registers all routes on the given mux, building the middleware
// chain for each route in a fixed order: Handler → Method → Limiter → Auth → Csrf → CORS.
func RegisterRoutes(mux *http.ServeMux, routes []Route, csrfToken string, authService *auth.AuthService, trustedProxies []string) {
	for _, route := range routes {
		h := route.Handler

		if route.Method != "" {
			method := route.Method
			inner := h
			h = func(w http.ResponseWriter, r *http.Request) {
				if r.Method != method && r.Method != "OPTIONS" {
					http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
					return
				}
				inner(w, r)
			}
		}

		if route.Limiter != nil {
			h = route.Limiter.Limit(h)
		}

		if route.Auth {
			h = RequireAuth(authService, trustedProxies, h)
		}

		if route.Csrf {
			h = RequireCsrfToken(csrfToken, h)
		}

		h = CORS(h)

		mux.HandleFunc(route.Pattern, h)
	}
}
