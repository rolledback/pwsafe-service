package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rolledback/pwsafe-service/backend/internal/models"
	"github.com/rolledback/pwsafe-service/backend/internal/provider/mock"
	"github.com/rolledback/pwsafe-service/backend/internal/service"
)

func newTestProvidersHandler(t *testing.T) (*ProvidersHandler, *mock.Provider) {
	t.Helper()
	mockProvider := mock.NewProvider("testprovider")
	dataDir := t.TempDir()
	ctx := context.Background()
	svc := service.NewSyncableSafesService(ctx, dataDir, mockProvider, 0, 10<<20)
	t.Cleanup(svc.Stop)

	services := map[string]*service.SyncableSafesService{
		"testprovider": svc,
	}
	handler := NewProvidersHandler(services, nil)
	return handler, mockProvider
}

func TestSaveFiles_OversizedBody_Rejected(t *testing.T) {
	handler, _ := newTestProvidersHandler(t)

	bigBody := `{"files":[{"id":"` + strings.Repeat("a", 9000) + `"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/providers/testprovider/files", bytes.NewReader([]byte(bigBody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Route(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected status 413 for oversized body, got %d", w.Code)
	}

	var errResp models.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if !strings.Contains(errResp.Error, "too large") {
		t.Errorf("Expected error to mention 'too large', got %q", errResp.Error)
	}
}

func TestSaveFiles_ValidBody_Accepted(t *testing.T) {
	handler, _ := newTestProvidersHandler(t)

	reqBody := map[string]interface{}{
		"files": []map[string]interface{}{
			{"id": "f1", "name": "test.psafe3", "path": "/", "size": 1024, "selected": true},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPut, "/api/providers/testprovider/files", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Route(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for valid body, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// newTestProvidersHandlerWithID creates a ProvidersHandler with a single mock
// provider registered under the given ID.
func newTestProvidersHandlerWithID(t *testing.T, providerID string) (*ProvidersHandler, *mock.Provider) {
	t.Helper()
	p := mock.NewProvider(providerID)
	dataDir := t.TempDir()
	svc := service.NewSyncableSafesService(context.Background(), dataDir, p, 0, 10<<20)
	t.Cleanup(svc.Stop)

	services := map[string]*service.SyncableSafesService{providerID: svc}
	return NewProvidersHandler(services, nil), p
}

// TestCallback_ConfiguredVsUnconfigured_UniformResponse verifies that OAuth
// callback requests for configured and unconfigured providers produce an
// identical HTTP response (same status code, same Location header format).
func TestCallback_ConfiguredVsUnconfigured_UniformResponse(t *testing.T) {
	h, _ := newTestProvidersHandlerWithID(t, "onedrive")

	configured := httptest.NewRequest(http.MethodGet, "/api/providers/onedrive/auth/callback", nil)
	unconfigured := httptest.NewRequest(http.MethodGet, "/api/providers/gdrive/auth/callback", nil)

	wConf := httptest.NewRecorder()
	wUnconf := httptest.NewRecorder()

	h.Route(wConf, configured)
	h.Route(wUnconf, unconfigured)

	if wConf.Code != wUnconf.Code {
		t.Errorf("status codes differ: configured=%d unconfigured=%d", wConf.Code, wUnconf.Code)
	}
	if wConf.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", wConf.Code)
	}

	locConf := wConf.Header().Get("Location")
	locUnconf := wUnconf.Header().Get("Location")

	// Both should contain the generic "auth_error" parameter
	if locConf != "/web/add/onedrive?error=auth_error" {
		t.Errorf("unexpected Location for configured provider: %s", locConf)
	}
	if locUnconf != "/web/add/gdrive?error=auth_error" {
		t.Errorf("unexpected Location for unconfigured provider: %s", locUnconf)
	}
}

// TestCallback_NoCode_GenericError verifies that a callback without an
// authorization code redirects with the generic "auth_error" and never
// exposes descriptive error strings like "auth_failed".
func TestCallback_NoCode_GenericError(t *testing.T) {
	h, _ := newTestProvidersHandlerWithID(t, "onedrive")

	req := httptest.NewRequest(http.MethodGet, "/api/providers/onedrive/auth/callback?error_description=access_denied", nil)
	w := httptest.NewRecorder()
	h.Route(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/web/add/onedrive?error=auth_error" {
		t.Errorf("expected generic auth_error redirect, got %s", loc)
	}
}

// TestCallback_TokenExchangeFailed_GenericError verifies that a token
// exchange failure redirects with "auth_error" instead of the old
// "token_exchange_failed" message.
func TestCallback_TokenExchangeFailed_GenericError(t *testing.T) {
	h, p := newTestProvidersHandlerWithID(t, "onedrive")
	p.AuthError = errors.New("simulated token failure")

	req := httptest.NewRequest(http.MethodGet, "/api/providers/onedrive/auth/callback?code=badcode&state=badstate", nil)
	w := httptest.NewRecorder()
	h.Route(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/web/add/onedrive?error=auth_error" {
		t.Errorf("expected generic auth_error redirect, got %s", loc)
	}
}

// TestCallback_UnconfiguredProvider_Redirect verifies that an unconfigured
// provider returns a 302 redirect (not a 404 JSON) on the callback path.
func TestCallback_UnconfiguredProvider_Redirect(t *testing.T) {
	h, _ := newTestProvidersHandlerWithID(t, "onedrive")

	req := httptest.NewRequest(http.MethodGet, "/api/providers/doesnotexist/auth/callback", nil)
	w := httptest.NewRecorder()
	h.Route(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("expected 302 for unconfigured provider callback, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/web/add/doesnotexist?error=auth_error" {
		t.Errorf("unexpected Location: %s", loc)
	}
}

// TestCallback_InvalidProviderID_SanitizedRedirect verifies that a
// malicious provider ID with injection characters is sanitized.
func TestCallback_InvalidProviderID_SanitizedRedirect(t *testing.T) {
	h, _ := newTestProvidersHandlerWithID(t, "onedrive")

	req := httptest.NewRequest(http.MethodGet, "/api/providers/evil%3Cscript%3E/auth/callback", nil)
	req.URL.Path = "/api/providers/evil<script>/auth/callback"
	w := httptest.NewRecorder()
	h.Route(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/web/add/unknown?error=auth_error" {
		t.Errorf("expected sanitized redirect, got %s", loc)
	}
}

// TestCallback_NonCallbackRoutes_StillReturn404 verifies that non-callback
// routes for unconfigured providers still return 404.
func TestCallback_NonCallbackRoutes_StillReturn404(t *testing.T) {
	h, _ := newTestProvidersHandlerWithID(t, "onedrive")

	req := httptest.NewRequest(http.MethodGet, "/api/providers/doesnotexist/status", nil)
	w := httptest.NewRecorder()
	h.Route(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-callback route on unconfigured provider, got %d", w.Code)
	}
}

// TestCallback_POSTMethod_UniformForConfiguredAndUnconfigured verifies that
// POST to the callback path returns the same 405 response regardless of
// whether the provider is configured, preventing method-based enumeration.
func TestCallback_POSTMethod_UniformForConfiguredAndUnconfigured(t *testing.T) {
	h, _ := newTestProvidersHandlerWithID(t, "onedrive")

	configured := httptest.NewRequest(http.MethodPost, "/api/providers/onedrive/auth/callback", nil)
	unconfigured := httptest.NewRequest(http.MethodPost, "/api/providers/doesnotexist/auth/callback", nil)

	wConf := httptest.NewRecorder()
	wUnconf := httptest.NewRecorder()

	h.Route(wConf, configured)
	h.Route(wUnconf, unconfigured)

	if wConf.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for configured provider POST callback, got %d", wConf.Code)
	}
	if wUnconf.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for unconfigured provider POST callback, got %d", wUnconf.Code)
	}
	if wConf.Code != wUnconf.Code {
		t.Errorf("status codes differ: configured=%d unconfigured=%d", wConf.Code, wUnconf.Code)
	}
}
