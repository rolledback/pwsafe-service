package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rolledback/pwsafe-service/backend/internal/models"
	"github.com/rolledback/pwsafe-service/backend/internal/service"
	"github.com/rolledback/pwsafe-service/backend/internal/testutil"
)

// Helper to get safe ID by name from list
func getSafeByName(handler *SafeHandler, name string) *models.SafeFile {
	req := httptest.NewRequest(http.MethodGet, "/api/safes", nil)
	w := httptest.NewRecorder()
	handler.ListSafes(w, req)

	var safes []models.SafeFile
	json.NewDecoder(w.Body).Decode(&safes)

	for _, safe := range safes {
		if safe.Name == name {
			return &safe
		}
	}
	return nil
}

func TestListSafes_Handler(t *testing.T) {
	tmpDir := testutil.SetupTestDataDir(t)
	service := service.NewSafeService(tmpDir, 10<<20)
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

	for _, safe := range safes {
		if safe.Provider == "" {
			t.Errorf("Expected provider field to be set for safe %s", safe.Name)
		}
		if safe.Path == "" {
			t.Errorf("Expected path field to be set for safe %s", safe.Name)
		}
		if safe.ID == "" {
			t.Errorf("Expected id field to be set for safe %s", safe.Name)
		}
	}
}

func TestUnlockSafe_Success(t *testing.T) {
	tmpDir := testutil.SetupTestDataDir(t)
	service := service.NewSafeService(tmpDir, 10<<20)
	handler := NewSafeHandler(service)

	// Get safe info first
	safe := getSafeByName(handler, "simple.psafe3")
	if safe == nil {
		t.Fatal("Could not find simple.psafe3 in safes list")
	}

	reqBody := models.UnlockRequest{Password: "password"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+safe.ID+"/unlock", bytes.NewReader(body))
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
	tmpDir := testutil.SetupTestDataDir(t)
	service := service.NewSafeService(tmpDir, 10<<20)
	handler := NewSafeHandler(service)

	safe := getSafeByName(handler, "simple.psafe3")
	if safe == nil {
		t.Fatal("Could not find simple.psafe3 in safes list")
	}

	reqBody := models.UnlockRequest{Password: "wrongpassword"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+safe.ID+"/unlock", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UnlockSafe(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestUnlockSafe_MissingPassword(t *testing.T) {
	tmpDir := testutil.SetupTestDataDir(t)
	service := service.NewSafeService(tmpDir, 10<<20)
	handler := NewSafeHandler(service)

	safe := getSafeByName(handler, "simple.psafe3")
	if safe == nil {
		t.Fatal("Could not find simple.psafe3 in safes list")
	}

	reqBody := models.UnlockRequest{Password: ""}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+safe.ID+"/unlock", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UnlockSafe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestUnlockSafe_NonexistentID(t *testing.T) {
	tmpDir := testutil.SetupTestDataDir(t)
	service := service.NewSafeService(tmpDir, 10<<20)
	handler := NewSafeHandler(service)

	reqBody := models.UnlockRequest{Password: "password"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/safes/nonexistent123/unlock", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UnlockSafe(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestUnlockSafe_InvalidJSON(t *testing.T) {
	tmpDir := testutil.SetupTestDataDir(t)
	service := service.NewSafeService(tmpDir, 10<<20)
	handler := NewSafeHandler(service)

	safe := getSafeByName(handler, "simple.psafe3")
	if safe == nil {
		t.Fatal("Could not find simple.psafe3 in safes list")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+safe.ID+"/unlock", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UnlockSafe(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestGetEntryPassword_Success(t *testing.T) {
	tmpDir := testutil.SetupTestDataDir(t)
	service := service.NewSafeService(tmpDir, 10<<20)
	handler := NewSafeHandler(service)

	safe := getSafeByName(handler, "simple.psafe3")
	if safe == nil {
		t.Fatal("Could not find simple.psafe3 in safes list")
	}

	reqBody := models.EntryPasswordRequest{
		Password:  "password",
		EntryUUID: "c4dcfb52-b944-f141-af96-b746f184afe2",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+safe.ID+"/entry", bytes.NewReader(body))
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
	tmpDir := testutil.SetupTestDataDir(t)
	service := service.NewSafeService(tmpDir, 10<<20)
	handler := NewSafeHandler(service)

	safe := getSafeByName(handler, "simple.psafe3")
	if safe == nil {
		t.Fatal("Could not find simple.psafe3 in safes list")
	}

	reqBody := models.EntryPasswordRequest{
		Password:  "password",
		EntryUUID: "00000000-0000-0000-0000-000000000000",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+safe.ID+"/entry", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.GetEntryPassword(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestGetEntryPassword_MissingFields(t *testing.T) {
	tmpDir := testutil.SetupTestDataDir(t)
	service := service.NewSafeService(tmpDir, 10<<20)
	handler := NewSafeHandler(service)

	safe := getSafeByName(handler, "simple.psafe3")
	if safe == nil {
		t.Fatal("Could not find simple.psafe3 in safes list")
	}

	reqBody := models.EntryPasswordRequest{
		Password:  "",
		EntryUUID: "c4dcfb52-b944-f141-af96-b746f184afe2",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+safe.ID+"/entry", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.GetEntryPassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestGetEntryPassword_SpecialCharacters(t *testing.T) {
	tmpDir := testutil.SetupTestDataDir(t)
	service := service.NewSafeService(tmpDir, 10<<20)
	handler := NewSafeHandler(service)

	safe := getSafeByName(handler, "three.psafe3")
	if safe == nil {
		t.Fatal("Could not find three.psafe3 in safes list")
	}

	reqBody := models.EntryPasswordRequest{
		Password:  "three3#;",
		EntryUUID: "6f1738b6-4a22-314a-8bbf-5c3507f0d489",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/safes/"+safe.ID+"/entry", bytes.NewReader(body))
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
