package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/rolledback/pwsafe-service/backend/internal/models"
	"github.com/rolledback/pwsafe-service/backend/internal/service"
)

// ProviderInfo represents a provider in the list response
type ProviderInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Icon        string `json:"icon"`
	BrandColor  string `json:"brandColor"`
}

// ProvidersHandler handles HTTP requests for all providers
type ProvidersHandler struct {
	services map[string]*service.SyncableSafesService
}

// NewProvidersHandler creates a new providers handler
func NewProvidersHandler(services map[string]*service.SyncableSafesService) *ProvidersHandler {
	return &ProvidersHandler{
		services: services,
	}
}

// ListProviders handles GET /api/providers - lists all available providers
func (h *ProvidersHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET /api/providers")

	if r.Method != http.MethodGet {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	providers := make([]ProviderInfo, 0, len(h.services))
	for _, svc := range h.services {
		p := svc.Provider()
		providers = append(providers, ProviderInfo{
			ID:          p.ID(),
			DisplayName: p.DisplayName(),
			Icon:        p.Icon(),
			BrandColor:  p.BrandColor(),
		})
	}

	h.respondJSON(w, map[string]interface{}{"providers": providers}, http.StatusOK)
}

// Route handles all /api/providers/{id}/* requests
func (h *ProvidersHandler) Route(w http.ResponseWriter, r *http.Request) {
	// Parse provider ID and action from path
	// Path format: /api/providers/{id}/{action...}
	path := strings.TrimPrefix(r.URL.Path, "/api/providers/")
	parts := strings.SplitN(path, "/", 2)

	if len(parts) == 0 || parts[0] == "" {
		h.respondError(w, "Provider ID required", http.StatusBadRequest)
		return
	}

	providerID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	// Get the service for this provider
	svc, ok := h.services[providerID]
	if !ok {
		h.respondError(w, "Provider not found", http.StatusNotFound)
		return
	}

	// Route to appropriate handler
	switch action {
	case "status":
		h.getStatus(w, r, svc)
	case "auth/url":
		h.getAuthURL(w, r, svc)
	case "auth/callback":
		h.handleCallback(w, r, svc, providerID)
	case "disconnect":
		h.disconnect(w, r, svc)
	case "files":
		h.handleFiles(w, r, svc)
	case "sync":
		h.sync(w, r, svc)
	default:
		h.respondError(w, "Unknown action", http.StatusNotFound)
	}
}

func (h *ProvidersHandler) getStatus(w http.ResponseWriter, r *http.Request, svc *service.SyncableSafesService) {
	providerID := svc.Provider().ID()
	log.Printf("GET /api/providers/%s/status", providerID)

	if r.Method != http.MethodGet {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status, err := svc.GetProviderStatus(r.Context())
	if err != nil {
		log.Printf("Error getting %s status: %v", providerID, err)
		h.respondError(w, "Failed to get provider status", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, status, http.StatusOK)
}

func (h *ProvidersHandler) getAuthURL(w http.ResponseWriter, r *http.Request, svc *service.SyncableSafesService) {
	providerID := svc.Provider().ID()
	log.Printf("GET /api/providers/%s/auth/url", providerID)

	if r.Method != http.MethodGet {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authURL, err := svc.Provider().GetAuthURL(r.Context())
	if err != nil {
		log.Printf("Error getting %s auth URL: %v", providerID, err)
		h.respondError(w, "Failed to get auth URL", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, map[string]string{"url": authURL}, http.StatusOK)
}

func (h *ProvidersHandler) handleCallback(w http.ResponseWriter, r *http.Request, svc *service.SyncableSafesService, providerID string) {
	log.Printf("GET /api/providers/%s/auth/callback", providerID)

	if r.Method != http.MethodGet {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		errorDesc := r.URL.Query().Get("error_description")
		if errorDesc != "" {
			log.Printf("OAuth error for %s: %s", providerID, errorDesc)
		}
		http.Redirect(w, r, "/web/add/"+providerID+"?error=auth_failed", http.StatusFound)
		return
	}

	if err := svc.Provider().HandleCallback(r.Context(), code); err != nil {
		log.Printf("Error handling %s callback: %v", providerID, err)
		http.Redirect(w, r, "/web/add/"+providerID+"?error=token_exchange_failed", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/web/add/"+providerID, http.StatusFound)
}

func (h *ProvidersHandler) disconnect(w http.ResponseWriter, r *http.Request, svc *service.SyncableSafesService) {
	providerID := svc.Provider().ID()
	log.Printf("POST /api/providers/%s/disconnect", providerID)

	if r.Method != http.MethodPost {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := svc.Disconnect(r.Context()); err != nil {
		log.Printf("Error disconnecting %s: %v", providerID, err)
		h.respondError(w, "Failed to disconnect provider", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, map[string]bool{"success": true}, http.StatusOK)
}

func (h *ProvidersHandler) handleFiles(w http.ResponseWriter, r *http.Request, svc *service.SyncableSafesService) {
	switch r.Method {
	case http.MethodGet:
		h.listFiles(w, r, svc)
	case http.MethodPut:
		h.saveFiles(w, r, svc)
	default:
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *ProvidersHandler) listFiles(w http.ResponseWriter, r *http.Request, svc *service.SyncableSafesService) {
	providerID := svc.Provider().ID()
	log.Printf("GET /api/providers/%s/files", providerID)

	files, err := svc.ListFiles(r.Context())
	if err != nil {
		log.Printf("Error listing %s files: %v", providerID, err)
		h.respondError(w, "Failed to list files", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, map[string]interface{}{"files": files}, http.StatusOK)
}

func (h *ProvidersHandler) saveFiles(w http.ResponseWriter, r *http.Request, svc *service.SyncableSafesService) {
	providerID := svc.Provider().ID()
	log.Printf("PUT /api/providers/%s/files", providerID)

	var req struct {
		Files []service.SelectedFile `json:"files"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := svc.SaveFiles(req.Files); err != nil {
		log.Printf("Error saving %s files: %v", providerID, err)
		h.respondError(w, "Failed to save files", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, map[string]bool{"success": true}, http.StatusOK)
}

func (h *ProvidersHandler) sync(w http.ResponseWriter, r *http.Request, svc *service.SyncableSafesService) {
	providerID := svc.Provider().ID()
	log.Printf("POST /api/providers/%s/sync", providerID)

	if r.Method != http.MethodPost {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	results, err := svc.Sync(r.Context())
	if err != nil {
		log.Printf("Error syncing %s files: %v", providerID, err)
		h.respondError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, map[string]interface{}{"results": results}, http.StatusOK)
}

func (h *ProvidersHandler) respondJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *ProvidersHandler) respondError(w http.ResponseWriter, message string, status int) {
	h.respondJSON(w, models.ErrorResponse{Error: message}, status)
}
