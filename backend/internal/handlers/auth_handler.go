package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rolledback/pwsafe-service/backend/internal/auth"
	"github.com/rolledback/pwsafe-service/backend/internal/middleware"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	authService *auth.AuthService
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(authService *auth.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
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
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check IP ban
	ip := middleware.GetClientIP(r)
	if h.authService.IsIPBanned(ip) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	mode := h.authService.GetMode()
	authenticated := false

	if mode == "secured" {
		sessionID := auth.GetSessionIDFromRequest(r)
		if sessionID != "" {
			authenticated = h.authService.IsAuthenticated(sessionID, ip)
		}
	} else if mode == "unsecured" {
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
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check IP ban
	ip := middleware.GetClientIP(r)
	if h.authService.IsIPBanned(ip) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

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
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract IP
	ip := middleware.GetClientIP(r)

	// Check IP ban
	if h.authService.IsIPBanned(ip) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	sessionID, err := h.authService.Login(req.Password, ip)
	if err != nil {
		// Record failed login attempt
		h.authService.RecordRateLimitHit(ip)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Determine if we should set Secure flag (check X-Forwarded-Proto or TLS)
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	auth.SetSessionCookie(w, sessionID, secure, h.authService.GetSessionTimeout())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Logout clears the session
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := auth.GetSessionIDFromRequest(r)
	if sessionID != "" {
		h.authService.Logout(sessionID)
	}

	auth.ClearSessionCookie(w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
