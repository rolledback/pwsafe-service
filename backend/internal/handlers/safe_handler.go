package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/rolledback/pwsafe-service/backend/internal/models"
	"github.com/rolledback/pwsafe-service/backend/internal/service"
)

type SafeHandler struct {
	safeService *service.SafeService
}

func NewSafeHandler(safeService *service.SafeService) *SafeHandler {
	return &SafeHandler{
		safeService: safeService,
	}
}

func (h *SafeHandler) ListSafes(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET /api/safes")

	if r.Method != http.MethodGet {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	safes, err := h.safeService.ListSafes()
	if err != nil {
		log.Printf("Error listing safes: %v", err)
		h.respondError(w, "Failed to list safes", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, safes, http.StatusOK)
}

func (h *SafeHandler) UnlockSafe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	safePath := extractSafePath(r.URL.Path, "/api/safes/", "/unlock")
	if safePath == "" {
		h.respondError(w, "Invalid safe path", http.StatusBadRequest)
		return
	}

	log.Printf("POST /api/safes/%s/unlock", safePath)

	var req models.UnlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		h.respondError(w, "Password is required", http.StatusBadRequest)
		return
	}

	structure, err := h.safeService.UnlockSafe(safePath, req.Password)
	if err != nil {
		log.Printf("Error unlocking safe %s: %v", safePath, err)
		if strings.Contains(err.Error(), "not found") {
			h.respondError(w, "Safe file not found", http.StatusNotFound)
		} else if strings.Contains(err.Error(), "directory traversal") || strings.Contains(err.Error(), "invalid safe path") {
			h.respondError(w, "Invalid safe path", http.StatusBadRequest)
		} else {
			h.respondError(w, "Failed to unlock safe - invalid password or corrupted file", http.StatusUnauthorized)
		}
		return
	}

	h.respondJSON(w, structure, http.StatusOK)
}

func (h *SafeHandler) GetEntryPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	safePath := extractSafePath(r.URL.Path, "/api/safes/", "/entry")
	if safePath == "" {
		h.respondError(w, "Invalid safe path", http.StatusBadRequest)
		return
	}

	log.Printf("POST /api/safes/%s/entry", safePath)

	var req models.EntryPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Password == "" || req.EntryUUID == "" {
		h.respondError(w, "Password and entryUuid are required", http.StatusBadRequest)
		return
	}

	password, err := h.safeService.GetEntryPassword(safePath, req.Password, req.EntryUUID)
	if err != nil {
		log.Printf("Error getting entry password for %s in %s: %v", req.EntryUUID, safePath, err)
		if strings.Contains(err.Error(), "not found") {
			h.respondError(w, err.Error(), http.StatusNotFound)
		} else if strings.Contains(err.Error(), "directory traversal") || strings.Contains(err.Error(), "invalid safe path") {
			h.respondError(w, "Invalid safe path", http.StatusBadRequest)
		} else {
			h.respondError(w, "Failed to get entry password", http.StatusUnauthorized)
		}
		return
	}

	response := models.EntryPasswordResponse{
		Password: password,
	}
	h.respondJSON(w, response, http.StatusOK)
}

func (h *SafeHandler) respondJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *SafeHandler) respondError(w http.ResponseWriter, message string, status int) {
	h.respondJSON(w, models.ErrorResponse{Error: message}, status)
}

// extractSafePath extracts and URL-decodes the safe path from the URL.
// The path is expected to be URL-encoded (e.g., %2Fsafes%2Ffile.psafe3 for /safes/file.psafe3)
func extractSafePath(urlPath, prefix, suffix string) string {
	path := strings.TrimPrefix(urlPath, prefix)
	path = strings.TrimSuffix(path, suffix)
	
	// URL-decode the path
	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		return ""
	}
	
	return decodedPath
}
