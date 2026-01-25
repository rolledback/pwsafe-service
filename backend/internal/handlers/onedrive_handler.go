package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/rolledback/pwsafe-service/backend/internal/models"
	"github.com/rolledback/pwsafe-service/backend/internal/service"
)

// OneDriveHandler handles HTTP requests for the OneDrive provider
// using the new SyncableSafesService architecture
type OneDriveHandler struct {
	syncService *service.SyncableSafesService
}

// NewOneDriveHandler creates a new OneDrive handler
func NewOneDriveHandler(syncService *service.SyncableSafesService) *OneDriveHandler {
	return &OneDriveHandler{
		syncService: syncService,
	}
}

func (h *OneDriveHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET /api/onedrive/status")

	if r.Method != http.MethodGet {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status, err := h.syncService.GetProviderStatus(r.Context())
	if err != nil {
		log.Printf("Error getting OneDrive status: %v", err)
		h.respondError(w, "Failed to get OneDrive status", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, status, http.StatusOK)
}

func (h *OneDriveHandler) GetAuthURL(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET /api/onedrive/auth/url")

	if r.Method != http.MethodGet {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authURL, err := h.syncService.Provider().GetAuthURL(r.Context())
	if err != nil {
		log.Printf("Error getting OneDrive auth URL: %v", err)
		h.respondError(w, "Failed to get auth URL", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, map[string]string{"url": authURL}, http.StatusOK)
}

func (h *OneDriveHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET /api/onedrive/auth/callback")

	if r.Method != http.MethodGet {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		errorDesc := r.URL.Query().Get("error_description")
		if errorDesc != "" {
			log.Printf("OAuth error: %s", errorDesc)
		}
		http.Redirect(w, r, "/web/add/onedrive?error=auth_failed", http.StatusFound)
		return
	}

	if err := h.syncService.Provider().HandleCallback(r.Context(), code); err != nil {
		log.Printf("Error handling OneDrive callback: %v", err)
		http.Redirect(w, r, "/web/add/onedrive?error=token_exchange_failed", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/web/add/onedrive", http.StatusFound)
}

func (h *OneDriveHandler) Disconnect(w http.ResponseWriter, r *http.Request) {
	log.Printf("POST /api/onedrive/disconnect")

	if r.Method != http.MethodPost {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := h.syncService.Disconnect(r.Context()); err != nil {
		log.Printf("Error disconnecting OneDrive: %v", err)
		h.respondError(w, "Failed to disconnect OneDrive", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, map[string]bool{"success": true}, http.StatusOK)
}

func (h *OneDriveHandler) HandleFiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listFiles(w, r)
	case http.MethodPut:
		h.saveFiles(w, r)
	default:
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *OneDriveHandler) listFiles(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET /api/onedrive/files")

	files, err := h.syncService.ListFiles(r.Context())
	if err != nil {
		log.Printf("Error listing OneDrive files: %v", err)
		h.respondError(w, "Failed to list files", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, map[string]interface{}{"files": files}, http.StatusOK)
}

func (h *OneDriveHandler) saveFiles(w http.ResponseWriter, r *http.Request) {
	log.Printf("PUT /api/onedrive/files")

	var req struct {
		Files []service.SelectedFile `json:"files"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.syncService.SaveFiles(req.Files); err != nil {
		log.Printf("Error saving OneDrive files: %v", err)
		h.respondError(w, "Failed to save files", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, map[string]bool{"success": true}, http.StatusOK)
}

func (h *OneDriveHandler) Sync(w http.ResponseWriter, r *http.Request) {
	log.Printf("POST /api/onedrive/sync")

	if r.Method != http.MethodPost {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	results, err := h.syncService.Sync(r.Context())
	if err != nil {
		log.Printf("Error syncing OneDrive files: %v", err)
		h.respondError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, map[string]interface{}{"results": results}, http.StatusOK)
}

func (h *OneDriveHandler) respondJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *OneDriveHandler) respondError(w http.ResponseWriter, message string, status int) {
	h.respondJSON(w, models.ErrorResponse{Error: message}, status)
}
