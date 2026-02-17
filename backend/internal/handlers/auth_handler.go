package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rolledback/pwsafe-service/backend/internal/auth"
	"github.com/rolledback/pwsafe-service/backend/internal/middleware"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	authService    *auth.AuthService
	trustedProxies []string
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(authService *auth.AuthService, trustedProxies []string) *AuthHandler {
	return &AuthHandler{authService: authService, trustedProxies: trustedProxies}
}

type authStatusResponse struct {
	Mode          string `json:"mode"`
	Authenticated bool   `json:"authenticated"`
}

type setupRequest struct {
	Mode     string `json:"mode"`
	Password string `json:"password,omitempty"`
}

type loginRequest struct {
	Password string `json:"password"`
}

// Status returns the current auth mode and whether the caller is authenticated
func (h *AuthHandler) Status(w http.ResponseWriter, r *http.Request) {
	ip := middleware.GetClientIP(r, h.trustedProxies)
	mode := h.authService.GetMode()
	authenticated := false

	if mode == "enabled" {
		sessionID := auth.GetSessionIDFromRequest(r)
		if sessionID != "" {
			authenticated = h.authService.IsAuthenticated(sessionID, ip)
		}
	} else if mode == "disabled" {
		authenticated = true
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(authStatusResponse{
		Mode:          mode,
		Authenticated: authenticated,
	})
}

// Setup handles first-time auth configuration
func (h *AuthHandler) Setup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024) // 1KB limit for auth JSON
	var req setupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.authService.Setup(req.Mode, req.Password); err != nil {
		if err.Error() == "auth mode already configured" {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Login handles password authentication and session creation
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024) // 1KB limit for auth JSON
	ip := middleware.GetClientIP(r, h.trustedProxies)

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	sessionID, err := h.authService.Login(req.Password, ip)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Determine if we should set Secure flag (check X-Forwarded-Proto only if trusted)
	remoteIP := middleware.GetClientIP(r, nil) // raw remote IP for trust check
	secure := r.TLS != nil
	if !secure && middleware.IsTrustedProxy(remoteIP, h.trustedProxies) {
		secure = r.Header.Get("X-Forwarded-Proto") == "https"
	}
	auth.SetSessionCookie(w, sessionID, secure, h.authService.GetSessionTimeout())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Logout clears the session
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sessionID := auth.GetSessionIDFromRequest(r)
	if sessionID != "" {
		h.authService.Logout(sessionID)
	}

	auth.ClearSessionCookie(w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
