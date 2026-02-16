package handlers

import (
	"encoding/json"
	"log"
	"net/http"
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
	safes, err := h.safeService.ListSafes()
	if err != nil {
		log.Printf("Error listing safes: %v", err)
		h.respondError(w, "Failed to list safes", http.StatusInternalServerError)
		return
	}

	h.respondJSON(w, safes, http.StatusOK)
}

func (h *SafeHandler) UnlockSafe(w http.ResponseWriter, r *http.Request) {
	// Extract ID from URL: /api/safes/{id}/unlock
	id := extractSafeID(r.URL.Path, "/api/safes/", "/unlock")
	if id == "" {
		h.respondError(w, "Invalid safe identifier", http.StatusBadRequest)
		return
	}

	// Resolve ID to path
	ref, err := h.safeService.ResolvePath(id)
	if err != nil {
		log.Printf("Error resolving safe ID %s: %v", id, err)
		h.respondError(w, "Safe not found", http.StatusNotFound)
		return
	}

	var req models.UnlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		h.respondError(w, "Password is required", http.StatusBadRequest)
		return
	}

	structure, err := h.safeService.UnlockSafe(ref.Path, req.Password)
	if err != nil {
		log.Printf("Error unlocking safe %s: %v", ref.Path, err)
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
	// Extract ID from URL: /api/safes/{id}/entry
	id := extractSafeID(r.URL.Path, "/api/safes/", "/entry")
	if id == "" {
		h.respondError(w, "Invalid safe identifier", http.StatusBadRequest)
		return
	}

	// Resolve ID to path
	ref, err := h.safeService.ResolvePath(id)
	if err != nil {
		log.Printf("Error resolving safe ID %s: %v", id, err)
		h.respondError(w, "Safe not found", http.StatusNotFound)
		return
	}

	var req models.EntryPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Password == "" || req.EntryUUID == "" {
		h.respondError(w, "Password and entryUuid are required", http.StatusBadRequest)
		return
	}

	password, err := h.safeService.GetEntryPassword(ref.Path, req.Password, req.EntryUUID)
	if err != nil {
		log.Printf("Error getting entry password for %s in %s: %v", req.EntryUUID, ref.Path, err)
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

// extractSafeID extracts the safe ID from URL path
// URL format: {prefix}{id}{suffix}
func extractSafeID(urlPath, prefix, suffix string) string {
	path := strings.TrimPrefix(urlPath, prefix)
	path = strings.TrimSuffix(path, suffix)
	return path
}
