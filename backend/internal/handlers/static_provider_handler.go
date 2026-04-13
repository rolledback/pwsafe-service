package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rolledback/pwsafe-service/backend/internal/models"
	"github.com/rolledback/pwsafe-service/backend/internal/service"
)

// StaticProviderHandler handles HTTP requests for static safe operations (upload, delete)
type StaticProviderHandler struct {
	staticDir       string // data/static directory
	maxSafeFileSize int64
	safeService     *service.SafeService
}

// NewStaticProviderHandler creates a new static provider handler
// dataDir is the base data directory; static files go in dataDir/static
func NewStaticProviderHandler(dataDir string, safeService *service.SafeService, maxSafeFileSize int64) *StaticProviderHandler {
	staticDir := filepath.Join(dataDir, "static")
	// Auto-create static directory
	if err := os.MkdirAll(staticDir, 0700); err != nil {
		log.Printf("Warning: failed to create static directory: %v", err)
	}
	return &StaticProviderHandler{
		staticDir:       staticDir,
		maxSafeFileSize: maxSafeFileSize,
		safeService:     safeService,
	}
}

// Route handles all /api/providers/static/* requests
func (h *StaticProviderHandler) Route(w http.ResponseWriter, r *http.Request) {
	// Parse action from path: /api/providers/static/{action...}
	path := strings.TrimPrefix(r.URL.Path, "/api/providers/static/")

	if strings.HasPrefix(path, "files") {
		h.handleFiles(w, r, strings.TrimPrefix(path, "files"))
	} else {
		h.respondError(w, "Unknown action", http.StatusNotFound)
	}
}

func (h *StaticProviderHandler) handleFiles(w http.ResponseWriter, r *http.Request, subpath string) {
	// subpath is empty for /files, or /filename for /files/filename
	subpath = strings.TrimPrefix(subpath, "/")

	switch r.Method {
	case http.MethodPost:
		if subpath != "" {
			h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.uploadFile(w, r)
	case http.MethodDelete:
		if subpath == "" {
			h.respondError(w, "Filename required", http.StatusBadRequest)
			return
		}
		h.deleteFile(w, r, subpath)
	default:
		h.respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *StaticProviderHandler) uploadFile(w http.ResponseWriter, r *http.Request) {
	// Cap total request body to maxSafeFileSize + 1MB overhead for multipart headers
	r.Body = http.MaxBytesReader(w, r.Body, h.maxSafeFileSize+1<<20)

	// Parse multipart form (limit in-memory buffering to 10MB)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		log.Printf("Error parsing multipart form: %v", err)
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			h.respondError(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.respondError(w, "Failed to parse upload", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		log.Printf("Error getting form file: %v", err)
		h.respondError(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate and sanitize filename
	filename := h.sanitizeFilename(header.Filename)
	if filename == "" {
		h.respondError(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// Validate extension
	if !strings.HasSuffix(strings.ToLower(filename), ".psafe3") {
		h.respondError(w, "Only .psafe3 files are allowed", http.StatusBadRequest)
		return
	}

	destPath := filepath.Join(h.staticDir, filename)

	// Check if file exists
	if _, err := os.Stat(destPath); err == nil {
		// File exists, check for overwrite flag
		overwrite := r.URL.Query().Get("overwrite") == "true"
		if !overwrite {
			h.respondJSON(w, map[string]interface{}{
				"exists": true,
				"name":   filename,
			}, http.StatusConflict)
			return
		}
	}

	// Create destination file
	dst, err := os.Create(destPath)
	if err != nil {
		log.Printf("Error creating file %s: %v", destPath, err)
		h.respondError(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	// Copy content with size limit enforcement
	limitedFile := io.LimitReader(file, h.maxSafeFileSize+1)
	written, err := io.Copy(dst, limitedFile)
	if err != nil {
		dst.Close()
		os.Remove(destPath)
		log.Printf("Error writing file %s: %v", destPath, err)
		h.respondError(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	dst.Close()
	if written > h.maxSafeFileSize {
		os.Remove(destPath)
		h.respondError(w, fmt.Sprintf("File exceeds maximum size (%d bytes)", h.maxSafeFileSize), http.StatusRequestEntityTooLarge)
		return
	}

	log.Printf("Uploaded static safe: %s", filename)

	// Refresh cache so new safe gets an ID
	if err := h.safeService.RefreshCache(); err != nil {
		log.Printf("Warning: failed to refresh safe ID cache after upload: %v", err)
	}

	h.respondJSON(w, map[string]interface{}{
		"success": true,
		"name":    filename,
	}, http.StatusOK)
}

func (h *StaticProviderHandler) deleteFile(w http.ResponseWriter, r *http.Request, safeID string) {
	if safeID == "" {
		h.respondError(w, "Safe ID required", http.StatusBadRequest)
		return
	}

	// Resolve ID to path
	ref, err := h.safeService.ResolvePath(safeID)
	if err != nil {
		h.respondError(w, "Safe not found", http.StatusNotFound)
		return
	}

	// Only allow deleting static provider safes
	if ref.Provider != "static" {
		h.respondError(w, "Can only delete static safes", http.StatusBadRequest)
		return
	}

	// Validate and get absolute path
	absPath, err := h.safeService.ValidateSafePath(ref.Path)
	if err != nil {
		h.respondError(w, "Invalid safe path", http.StatusBadRequest)
		return
	}

	// Delete the file
	if err := os.Remove(absPath); err != nil {
		log.Printf("Error deleting file %s: %v", absPath, err)
		h.respondError(w, "Failed to delete file", http.StatusInternalServerError)
		return
	}

	log.Printf("Deleted static safe: %s (id: %s)", ref.Path, safeID)

	// Refresh cache to remove deleted safe
	if err := h.safeService.RefreshCache(); err != nil {
		log.Printf("Warning: failed to refresh safe ID cache after delete: %v", err)
	}

	h.respondJSON(w, map[string]bool{"success": true}, http.StatusOK)
}

// sanitizeFilename removes path components and invalid characters from filename
func (h *StaticProviderHandler) sanitizeFilename(filename string) string {
	// Get just the base name (remove any path components)
	filename = filepath.Base(filename)

	// Reject if it's a special path
	if filename == "." || filename == ".." || filename == "" {
		return ""
	}

	// Remove any characters that could be problematic
	// Allow alphanumeric, dash, underscore, dot, space
	reg := regexp.MustCompile(`[^a-zA-Z0-9\-_. ]`)
	filename = reg.ReplaceAllString(filename, "")

	// Trim spaces and dots from ends
	filename = strings.Trim(filename, " .")

	// Limit length
	if len(filename) > 255 {
		filename = filename[:255]
	}

	return filename
}

func (h *StaticProviderHandler) respondJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *StaticProviderHandler) respondError(w http.ResponseWriter, message string, status int) {
	h.respondJSON(w, models.ErrorResponse{Error: message}, status)
}
