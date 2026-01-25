package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rolledback/pwsafe-service/backend/internal/models"
	"github.com/rolledback/pwsafe-service/backend/internal/service"
)

func TestListSafes_Handler(t *testing.T) {
	service := service.NewSafeService("../../testdata")
	handler := NewSafeHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/safes", nil)
	w := httptest.NewRecorder()

	handler.ListSafes(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var safes []models.SafeFile
	if err := json.NewDecoder(w.Body).Decode(&safes); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(safes) < 2 {
		t.Errorf("Expected at least 2 safes, got %d", len(safes))
	}

	// Verify source field is present
	for _, safe := range safes {
		if safe.Provider == "" {
			t.Errorf("Expected source field to be set for safe %s", safe.Name)
		}
		if safe.Path == "" {
			t.Errorf("Expected path field to be set for safe %s", safe.Name)
		}
	}
}

func TestListSafes_WrongMethod(t *testing.T) {
	service := service.NewSafeService("../../testdata")
	handler := NewSafeHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/safes", nil)
	w := httptest.NewRecorder()

	handler.ListSafes(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestUnlockSafe_Success(t *testing.T) {
	service := service.NewSafeService("../../testdata")
	handler := NewSafeHandler(service)

	reqBody := models.UnlockRequest{Password: "password"}
	body, _ := json.Marshal(reqBody)

	// URL-encode the path
	encodedPath := url.PathEscape("/testdata/simple.psafe3")
	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+encodedPath+"/unlock", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UnlockSafe(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var structure models.SafeStructure
	if err := json.NewDecoder(w.Body).Decode(&structure); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(structure.Groups) != 1 {
		t.Errorf("Expected 1 group, got %d", len(structure.Groups))
	}
}

func TestUnlockSafe_WrongPassword(t *testing.T) {
	service := service.NewSafeService("../../testdata")
	handler := NewSafeHandler(service)

	reqBody := models.UnlockRequest{Password: "wrongpassword"}
	body, _ := json.Marshal(reqBody)

	encodedPath := url.PathEscape("/testdata/simple.psafe3")
	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+encodedPath+"/unlock", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UnlockSafe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestUnlockSafe_MissingPassword(t *testing.T) {
	service := service.NewSafeService("../../testdata")
	handler := NewSafeHandler(service)

	reqBody := models.UnlockRequest{Password: ""}
	body, _ := json.Marshal(reqBody)

	encodedPath := url.PathEscape("/testdata/simple.psafe3")
	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+encodedPath+"/unlock", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UnlockSafe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestUnlockSafe_NonexistentFile(t *testing.T) {
	service := service.NewSafeService("../../testdata")
	handler := NewSafeHandler(service)

	reqBody := models.UnlockRequest{Password: "password"}
	body, _ := json.Marshal(reqBody)

	encodedPath := url.PathEscape("/testdata/nonexistent.psafe3")
	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+encodedPath+"/unlock", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UnlockSafe(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestUnlockSafe_InvalidJSON(t *testing.T) {
	service := service.NewSafeService("../../testdata")
	handler := NewSafeHandler(service)

	encodedPath := url.PathEscape("/testdata/simple.psafe3")
	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+encodedPath+"/unlock", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UnlockSafe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestUnlockSafe_DirectoryTraversal(t *testing.T) {
	service := service.NewSafeService("../../testdata")
	handler := NewSafeHandler(service)

	reqBody := models.UnlockRequest{Password: "password"}
	body, _ := json.Marshal(reqBody)

	encodedPath := url.PathEscape("/testdata/../../../etc/passwd")
	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+encodedPath+"/unlock", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UnlockSafe(w, req)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
		t.Errorf("Expected status 400 or 404 for directory traversal, got %d", w.Code)
	}
}

func TestGetEntryPassword_Success(t *testing.T) {
	service := service.NewSafeService("../../testdata")
	handler := NewSafeHandler(service)

	reqBody := models.EntryPasswordRequest{
		Password:  "password",
		EntryUUID: "c4dcfb52-b944-f141-af96-b746f184afe2",
	}
	body, _ := json.Marshal(reqBody)

	encodedPath := url.PathEscape("/testdata/simple.psafe3")
	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+encodedPath+"/entry", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.GetEntryPassword(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response models.EntryPasswordResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Password != "password" {
		t.Errorf("Expected password 'password', got '%s'", response.Password)
	}
}

func TestGetEntryPassword_WrongUUID(t *testing.T) {
	service := service.NewSafeService("../../testdata")
	handler := NewSafeHandler(service)

	reqBody := models.EntryPasswordRequest{
		Password:  "password",
		EntryUUID: "00000000-0000-0000-0000-000000000000",
	}
	body, _ := json.Marshal(reqBody)

	encodedPath := url.PathEscape("/testdata/simple.psafe3")
	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+encodedPath+"/entry", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.GetEntryPassword(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestGetEntryPassword_MissingFields(t *testing.T) {
	service := service.NewSafeService("../../testdata")
	handler := NewSafeHandler(service)

	reqBody := models.EntryPasswordRequest{
		Password:  "",
		EntryUUID: "c4dcfb52-b944-f141-af96-b746f184afe2",
	}
	body, _ := json.Marshal(reqBody)

	encodedPath := url.PathEscape("/testdata/simple.psafe3")
	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+encodedPath+"/entry", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.GetEntryPassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestGetEntryPassword_SpecialCharacters(t *testing.T) {
	service := service.NewSafeService("../../testdata")
	handler := NewSafeHandler(service)

	reqBody := models.EntryPasswordRequest{
		Password:  "three3#;",
		EntryUUID: "6f1738b6-4a22-314a-8bbf-5c3507f0d489",
	}
	body, _ := json.Marshal(reqBody)

	encodedPath := url.PathEscape("/testdata/three.psafe3")
	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+encodedPath+"/entry", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.GetEntryPassword(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var response models.EntryPasswordResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Password != "three1!@$%^&*()" {
		t.Errorf("Expected password with special chars, got '%s'", response.Password)
	}
}
