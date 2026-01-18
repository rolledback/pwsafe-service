package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/rolledback/pwsafe-service/backend/internal/models"
	"github.com/rolledback/pwsafe-service/backend/internal/service"
)

type OneDriveHandler struct {
	onedriveService *service.OneDriveService
}

func NewOneDriveHandler(onedriveService *service.OneDriveService) *OneDriveHandler {
	return &OneDriveHandler{
		onedriveService: onedriveService,
	}
}

func (h *OneDriveHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET /api/onedrive/status")

	if r.Method != http.MethodGet {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status, err := h.onedriveService.GetStatus()
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

	authURL, err := h.onedriveService.GetAuthURL()
	if err != nil {
		log.Printf("Error getting OneDrive auth URL: %v", err)
		h.respondError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, authURL, http.StatusOK)
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

	if err := h.onedriveService.HandleCallback(code); err != nil {
		log.Printf("Error handling OneDrive callback: %v", err)
		http.Redirect(w, r, "/web/add/onedrive?error=token_exchange_failed", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/web/add/onedrive", http.StatusFound)
}

func (h *OneDriveHandler) respondJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *OneDriveHandler) respondError(w http.ResponseWriter, message string, status int) {
	h.respondJSON(w, models.ErrorResponse{Error: message}, status)
}

func (h *OneDriveHandler) Disconnect(w http.ResponseWriter, r *http.Request) {
	log.Printf("POST /api/onedrive/disconnect")

	if r.Method != http.MethodPost {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := h.onedriveService.Disconnect(); err != nil {
		log.Printf("Error disconnecting OneDrive: %v", err)
		h.respondError(w, "Failed to disconnect OneDrive", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, map[string]bool{"success": true}, http.StatusOK)
}

func (h *OneDriveHandler) HandleFiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getFiles(w, r)
	case http.MethodPut:
		h.putFiles(w, r)
	default:
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *OneDriveHandler) getFiles(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET /api/onedrive/files")

	files, err := h.onedriveService.ListFiles()
	if err != nil {
		log.Printf("Error listing OneDrive files: %v", err)
		h.respondError(w, "Failed to list files", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, files, http.StatusOK)
}

func (h *OneDriveHandler) putFiles(w http.ResponseWriter, r *http.Request) {
	log.Printf("PUT /api/onedrive/files")

	var req models.OneDriveFilesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.onedriveService.SaveFiles(req.Files); err != nil {
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

	result, err := h.onedriveService.Sync()
	if err != nil {
		log.Printf("Error syncing OneDrive files: %v", err)
		h.respondError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, result, http.StatusOK)
}
