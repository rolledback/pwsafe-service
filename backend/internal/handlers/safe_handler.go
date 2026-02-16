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
	ref, ok := h.resolveSafeFromURL(w, r, "/unlock")
	if !ok {
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
		h.handleSafeError(w, err, "Error unlocking safe "+ref.Path)
		return
	}

	h.respondJSON(w, structure, http.StatusOK)
}

func (h *SafeHandler) GetEntryPassword(w http.ResponseWriter, r *http.Request) {
	ref, ok := h.resolveSafeFromURL(w, r, "/entry")
	if !ok {
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
		h.handleSafeError(w, err, "Error getting entry password for "+req.EntryUUID+" in "+ref.Path)
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

// resolveSafeFromURL extracts the safe ID from URL and resolves it to a SafeRef.
// Returns nil and false if an error occurred (error response already written).
func (h *SafeHandler) resolveSafeFromURL(w http.ResponseWriter, r *http.Request, suffix string) (service.SafeRef, bool) {
	id := extractSafeID(r.URL.Path, "/api/safes/", suffix)
	if id == "" {
		h.respondError(w, "Invalid safe identifier", http.StatusBadRequest)
		return service.SafeRef{}, false
	}

	ref, err := h.safeService.ResolvePath(id)
	if err != nil {
		log.Printf("Error resolving safe ID %s: %v", id, err)
		h.respondError(w, "Safe not found", http.StatusNotFound)
		return service.SafeRef{}, false
	}

	return ref, true
}

// handleSafeError classifies and responds to safe operation errors.
func (h *SafeHandler) handleSafeError(w http.ResponseWriter, err error, context string) {
	log.Printf("%s: %v", context, err)
	if strings.Contains(err.Error(), "not found") {
		h.respondError(w, err.Error(), http.StatusNotFound)
	} else if strings.Contains(err.Error(), "directory traversal") || strings.Contains(err.Error(), "invalid safe path") || strings.Contains(err.Error(), "path traversal") {
		h.respondError(w, "Invalid safe path", http.StatusBadRequest)
	} else {
		h.respondError(w, "Invalid password or corrupted file", http.StatusUnauthorized)
	}
}

// extractSafeID extracts the safe ID from URL path
// URL format: {prefix}{id}{suffix}
func extractSafeID(urlPath, prefix, suffix string) string {
	path := strings.TrimPrefix(urlPath, prefix)
	path = strings.TrimSuffix(path, suffix)
	return path
}
