package handlers

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rolledback/pwsafe-service/backend/internal/models"
)

// StaticProviderHandler handles HTTP requests for static safe operations (upload, delete)
type StaticProviderHandler struct {
	safesDirectory string
}

// NewStaticProviderHandler creates a new static provider handler
func NewStaticProviderHandler(safesDirectory string) *StaticProviderHandler {
	return &StaticProviderHandler{
		safesDirectory: safesDirectory,
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
	log.Printf("POST /api/providers/static/files")

	// Parse multipart form (limit to 10MB)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		log.Printf("Error parsing multipart form: %v", err)
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

	destPath := filepath.Join(h.safesDirectory, filename)

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
	defer dst.Close()

	// Copy content
	if _, err := io.Copy(dst, file); err != nil {
		log.Printf("Error writing file %s: %v", destPath, err)
		h.respondError(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	log.Printf("Uploaded static safe: %s", filename)
	h.respondJSON(w, map[string]interface{}{
		"success": true,
		"name":    filename,
	}, http.StatusOK)
}

func (h *StaticProviderHandler) deleteFile(w http.ResponseWriter, r *http.Request, filename string) {
	log.Printf("DELETE /api/providers/static/files/%s", filename)

	// Sanitize filename to prevent path traversal
	filename = h.sanitizeFilename(filename)
	if filename == "" {
		h.respondError(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// Validate extension
	if !strings.HasSuffix(strings.ToLower(filename), ".psafe3") {
		h.respondError(w, "Only .psafe3 files can be deleted", http.StatusBadRequest)
		return
	}

	destPath := filepath.Join(h.safesDirectory, filename)

	// Security: ensure the resolved path is still within safesDirectory
	absPath, err := filepath.Abs(destPath)
	if err != nil {
		h.respondError(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	absSafesDir, err := filepath.Abs(h.safesDirectory)
	if err != nil {
		h.respondError(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	if !strings.HasPrefix(absPath, absSafesDir+string(filepath.Separator)) {
		h.respondError(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// Check if file exists
	if _, err := os.Stat(destPath); os.IsNotExist(err) {
		h.respondError(w, "File not found", http.StatusNotFound)
		return
	}

	// Delete the file
	if err := os.Remove(destPath); err != nil {
		log.Printf("Error deleting file %s: %v", destPath, err)
		h.respondError(w, "Failed to delete file", http.StatusInternalServerError)
		return
	}

	log.Printf("Deleted static safe: %s", filename)
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
