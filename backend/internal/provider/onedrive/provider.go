package onedrive

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rolledback/pwsafe-service/backend/internal/provider"
)

const (
	msAuthority        = "https://login.microsoftonline.com/consumers"
	msAuthorizeURL     = msAuthority + "/oauth2/v2.0/authorize"
	msTokenURL         = msAuthority + "/oauth2/v2.0/token"
	msGraphURL         = "https://graph.microsoft.com/v1.0"
	onedriveScopes     = "Files.Read User.Read offline_access"
	codeVerifierMaxAge = 15 * time.Minute

	// OneDrive brand color (Microsoft blue)
	onedriveBrandColor = "#0078D4"

	// OneDrive icon as base64-encoded SVG data URL
	onedriveIcon = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgNS41IDMyIDIwLjUiPjx0aXRsZT5PZmZpY2VDb3JlMTBfMzJ4XzI0eF8yMHhfMTZ4XzAxLTIyLTIwMTk8L3RpdGxlPjxnIGlkPSJTVFlMRV9DT0xPUiI+PHBhdGggZD0iTTEyLjIwMjQ1LDExLjE5MjkybC4wMDAzMS0uMDAxMSw2LjcxNzY1LDQuMDIzNzksNC4wMDI5My0xLjY4NDUxLjAwMDE4LjAwMDY4QTYuNDc2OCw2LjQ3NjgsMCwwLDEsMjUuNSwxM2MuMTQ3NjQsMCwuMjkzNTguMDA2Ny40Mzg3OC4wMTYzOWExMC4wMDA3NSwxMC4wMDA3NSwwLDAsMC0xOC4wNDEtMy4wMTM4MUM3LjkzMiwxMC4wMDIxNSw3Ljk2NTcsMTAsOCwxMEE3Ljk2MDczLDcuOTYwNzMsMCwwLDEsMTIuMjAyNDUsMTEuMTkyOTJaIiBmaWxsPSIjMDM2NGI4Ii8+PHBhdGggZD0iTTEyLjIwMjc2LDExLjE5MTgybC0uMDAwMzEuMDAxMUE3Ljk2MDczLDcuOTYwNzMsMCwwLDAsOCwxMGMtLjAzNDMsMC0uMDY4MDUuMDAyMTUtLjEwMjIzLjAwMjU4QTcuOTk2NzYsNy45OTY3NiwwLDAsMCwxLjQzNzMyLDIyLjU3Mjc3bDUuOTI0LTIuNDkyOTIsMi42MzM0Mi0xLjEwODE5LDUuODYzNTMtMi40Njc0NiwzLjA2MjEzLTEuMjg4NTlaIiBmaWxsPSIjMDA3OGQ0Ii8+PHBhdGggZD0iTTI1LjkzODc4LDEzLjAxNjM5QzI1Ljc5MzU4LDEzLjAwNjcsMjUuNjQ3NjQsMTMsMjUuNSwxM2E2LjQ3NjgsNi40NzY4LDAsMCwwLTIuNTc2NDguNTMxNzhsLS4wMDAxOC0uMDAwNjgtNC4wMDI5MywxLjY4NDUxLDEuMTYwNzcuNjk1MjhMMjMuODg2MTEsMTguMTlsMS42NjAwOS45OTQzOCw1LjY3NjMzLDMuNDAwMDdhNi41MDAyLDYuNTAwMiwwLDAsMC01LjI4Mzc1LTkuNTY4MDVaIiBmaWxsPSIjMTQ5MGRmIi8+PHBhdGggZD0iTTI1LjU0NjIsMTkuMTg0MzcsMjMuODg2MTEsMTguMTlsLTMuODA0OTMtMi4yNzkxLTEuMTYwNzctLjY5NTI4TDE1Ljg1ODI4LDE2LjUwNDIsOS45OTQ3NSwxOC45NzE2Niw3LjM2MTMzLDIwLjA3OTg1bC01LjkyNCwyLjQ5MjkyQTcuOTg4ODksNy45ODg4OSwwLDAsMCw4LDI2SDI1LjVhNi40OTgzNyw2LjQ5ODM3LDAsMCwwLDUuNzIyNTMtMy40MTU1NloiIGZpbGw9IiMyOGE4ZWEiLz48L2c+PC9zdmc+"
)

// Settings represents the OneDrive provider settings from settings.json
type Settings struct {
	ClientID string `json:"clientId"`
}

// tokens is the internal struct for storing OAuth tokens
type tokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    string `json:"expiresAt"`
	AccountName  string `json:"accountName"`
	AccountEmail string `json:"accountEmail"`
}

// OneDriveProvider implements provider.SyncableSafesProvider
type OneDriveProvider struct {
	storageDir  string // The provider's directory (e.g., {safesDir}/onedrive)
	clientID    string
	redirectURI string
	tokenMutex  sync.Mutex
}

// Factory creates an OneDriveProvider from settings.json content
func Factory(providerDir string, baseURL string, settingsJSON []byte) (provider.SyncableSafesProvider, error) {
	var settings Settings
	if err := json.Unmarshal(settingsJSON, &settings); err != nil {
		return nil, fmt.Errorf("invalid settings.json: %w", err)
	}
	if settings.ClientID == "" {
		return nil, fmt.Errorf("clientId is required in settings.json")
	}

	// Callback URL derived from baseURL + fixed path
	redirectURI := strings.TrimSuffix(baseURL, "/") + "/api/providers/onedrive/auth/callback"

	return NewOneDriveProvider(providerDir, settings.ClientID, redirectURI), nil
}

// NewOneDriveProvider creates a new OneDrive provider
// storageDir is the provider's directory where tokens and data are stored
func NewOneDriveProvider(storageDir, clientID, redirectURI string) *OneDriveProvider {
	p := &OneDriveProvider{
		storageDir:  storageDir,
		clientID:    clientID,
		redirectURI: redirectURI,
	}
	// Clean up any stale code verifier from previous runs
	p.cleanupStaleCodeVerifier()
	return p
}

// ============ IDENTITY (2 methods) ============

func (p *OneDriveProvider) ID() string {
	return "onedrive"
}

func (p *OneDriveProvider) DisplayName() string {
	return "OneDrive"
}

// ============ METADATA (2 methods) ============

func (p *OneDriveProvider) Icon() string {
	return onedriveIcon
}

func (p *OneDriveProvider) BrandColor() string {
	return onedriveBrandColor
}

// ============ AUTH (4 methods) ============

func (p *OneDriveProvider) GetAuthURL(ctx context.Context) (string, error) {
	if p.clientID == "" {
		return "", fmt.Errorf("OneDrive client ID not configured")
	}

	// Generate PKCE code verifier and challenge
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	codeChallenge := generateCodeChallenge(codeVerifier)

	// Store code verifier for later use in callback
	if err := p.storeCodeVerifier(codeVerifier); err != nil {
		return "", fmt.Errorf("failed to store code verifier: %w", err)
	}

	params := url.Values{
		"client_id":             {p.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {p.redirectURI},
		"scope":                 {onedriveScopes},
		"response_mode":         {"query"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	return msAuthorizeURL + "?" + params.Encode(), nil
}

func (p *OneDriveProvider) HandleCallback(ctx context.Context, code string) error {
	if p.clientID == "" {
		return fmt.Errorf("OneDrive client ID not configured")
	}

	// Retrieve code verifier
	codeVerifier, err := p.loadCodeVerifier()
	if err != nil {
		return fmt.Errorf("failed to load code verifier: %w", err)
	}

	// Exchange code for tokens
	newTokens, err := p.exchangeCodeForTokens(code, codeVerifier)
	if err != nil {
		return fmt.Errorf("failed to exchange code for tokens: %w", err)
	}

	// Get user profile
	accountName, accountEmail, err := p.getUserProfile(newTokens.AccessToken)
	if err != nil {
		// Non-fatal: continue without profile info
		accountName = ""
		accountEmail = ""
	}
	newTokens.AccountName = accountName
	newTokens.AccountEmail = accountEmail

	// Store tokens
	if err := p.storeTokens(newTokens); err != nil {
		return fmt.Errorf("failed to store tokens: %w", err)
	}

	// Clean up code verifier
	p.deleteCodeVerifier()

	return nil
}

func (p *OneDriveProvider) Disconnect(ctx context.Context) error {
	// Remove tokens file
	tokensPath := filepath.Join(p.storageDir, ".tokens.json")
	if err := os.Remove(tokensPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	// Delete code verifier if exists
	p.deleteCodeVerifier()
	return nil
}

func (p *OneDriveProvider) GetConnectionStatus(ctx context.Context, attemptRefresh bool) (*provider.ConnectionStatus, error) {
	status := &provider.ConnectionStatus{}

	t, err := p.loadTokens()
	if err != nil {
		return status, nil // Not connected
	}

	if t.AccessToken == "" || t.RefreshToken == "" {
		return status, nil // Not connected
	}

	// Check if expiresAt is parseable - if not, tokens are corrupted and need reauth
	if t.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, t.ExpiresAt); err != nil {
			status.NeedsReauth = true
			return status, nil
		}
	}

	status.Connected = true
	status.AccountName = t.AccountName
	status.AccountEmail = t.AccountEmail

	// If requested, verify we can actually refresh the token
	if attemptRefresh {
		if _, err := p.getValidAccessToken(); err != nil {
			status.NeedsReauth = true
		}
	}

	return status, nil
}

// ============ REMOTE OPERATIONS (2 methods - the core primitives) ============

func (p *OneDriveProvider) ListRemoteFiles(ctx context.Context) ([]provider.RemoteFile, error) {
	accessToken, err := p.getValidAccessToken()
	if err != nil {
		return nil, err
	}

	searchURL := msGraphURL + "/me/drive/root/search(q='.psafe3')"
	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search failed with status %d: %s", resp.StatusCode, string(body))
	}

	var searchResp struct {
		Value []struct {
			ID              string `json:"id"`
			Name            string `json:"name"`
			ParentReference struct {
				Path string `json:"path"`
			} `json:"parentReference"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to decode search response: %w", err)
	}

	var files []provider.RemoteFile
	for _, item := range searchResp.Value {
		// Filter to only .psafe3 files (search may return partial matches)
		if !strings.HasSuffix(strings.ToLower(item.Name), ".psafe3") {
			continue
		}

		// Extract path, removing the "/drive/root:" prefix
		path := item.ParentReference.Path
		if idx := strings.Index(path, ":"); idx != -1 {
			path = path[idx+1:]
		}
		// URL-decode the path (Graph API returns URL-encoded paths)
		if decodedPath, err := url.PathUnescape(path); err == nil {
			path = decodedPath
		}
		if path == "" {
			path = "/"
		}

		files = append(files, provider.RemoteFile{
			ID:   item.ID,
			Name: item.Name,
			Path: path,
		})
	}

	return files, nil
}

func (p *OneDriveProvider) DownloadFile(ctx context.Context, fileID string) (*provider.DownloadResult, error) {
	accessToken, err := p.getValidAccessToken()
	if err != nil {
		return nil, err
	}

	downloadURL := fmt.Sprintf("%s/me/drive/items/%s/content", msGraphURL, fileID)
	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Return the body stream and last modified - caller is responsible for closing
	return &provider.DownloadResult{
		Content:      resp.Body,
		LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}

// ============ PRIVATE HELPERS (token management) ============

func (p *OneDriveProvider) tokensPath() string {
	return filepath.Join(p.storageDir, ".tokens.json")
}

func (p *OneDriveProvider) loadTokens() (*tokens, error) {
	data, err := os.ReadFile(p.tokensPath())
	if err != nil {
		return nil, err
	}
	var t tokens
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (p *OneDriveProvider) storeTokens(t *tokens) error {
	if err := os.MkdirAll(p.storageDir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.tokensPath(), data, 0600)
}

func (p *OneDriveProvider) getValidAccessToken() (string, error) {
	p.tokenMutex.Lock()
	defer p.tokenMutex.Unlock()

	t, err := p.loadTokens()
	if err != nil {
		return "", fmt.Errorf("no tokens found: %w", err)
	}

	if t.AccessToken == "" {
		return "", fmt.Errorf("no access token")
	}

	expiresAt, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return "", fmt.Errorf("invalid expiry time")
	}

	// If token is still valid, return it
	if time.Now().Before(expiresAt) {
		return t.AccessToken, nil
	}

	// Token expired - try to refresh
	if t.RefreshToken == "" {
		return "", fmt.Errorf("REAUTH_REQUIRED: token expired and no refresh token")
	}

	newTokens, err := p.refreshAccessToken(t)
	if err != nil {
		return "", err
	}

	return newTokens.AccessToken, nil
}

func (p *OneDriveProvider) refreshAccessToken(t *tokens) (*tokens, error) {
	formData := url.Values{
		"client_id":     {p.clientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.RefreshToken},
		"scope":         {onedriveScopes},
	}

	resp, err := http.PostForm(msTokenURL, formData)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if strings.Contains(string(body), "invalid_grant") {
			return nil, fmt.Errorf("REAUTH_REQUIRED: refresh token is invalid")
		}
		return nil, fmt.Errorf("refresh failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", err)
	}

	// Microsoft may or may not return a new refresh token
	newRefresh := tokenResp.RefreshToken
	if newRefresh == "" {
		newRefresh = t.RefreshToken
	}

	newTokens := &tokens{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: newRefresh,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339),
		AccountName:  t.AccountName,
		AccountEmail: t.AccountEmail,
	}

	if err := p.storeTokens(newTokens); err != nil {
		return nil, fmt.Errorf("failed to store refreshed tokens: %w", err)
	}

	return newTokens, nil
}

func (p *OneDriveProvider) exchangeCodeForTokens(code, codeVerifier string) (*tokens, error) {
	data := url.Values{
		"client_id":     {p.clientID},
		"code":          {code},
		"redirect_uri":  {p.redirectURI},
		"grant_type":    {"authorization_code"},
		"code_verifier": {codeVerifier},
	}

	resp, err := http.PostForm(msTokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return &tokens{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
	}, nil
}

func (p *OneDriveProvider) getUserProfile(accessToken string) (name, email string, err error) {
	req, err := http.NewRequest("GET", msGraphURL+"/me", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("failed to get user profile: status %d", resp.StatusCode)
	}

	var profile struct {
		DisplayName       string `json:"displayName"`
		UserPrincipalName string `json:"userPrincipalName"`
		Mail              string `json:"mail"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return "", "", err
	}

	email = profile.Mail
	if email == "" {
		email = profile.UserPrincipalName
	}

	return profile.DisplayName, email, nil
}

func (p *OneDriveProvider) storeCodeVerifier(verifier string) error {
	if err := os.MkdirAll(p.storageDir, 0700); err != nil {
		return err
	}
	verifierPath := filepath.Join(p.storageDir, ".code_verifier")
	return os.WriteFile(verifierPath, []byte(verifier), 0600)
}

func (p *OneDriveProvider) loadCodeVerifier() (string, error) {
	verifierPath := filepath.Join(p.storageDir, ".code_verifier")

	// Check file age before reading
	stat, err := os.Stat(verifierPath)
	if err != nil {
		return "", err
	}

	if time.Since(stat.ModTime()) > codeVerifierMaxAge {
		os.Remove(verifierPath)
		return "", fmt.Errorf("code verifier expired")
	}

	data, err := os.ReadFile(verifierPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (p *OneDriveProvider) deleteCodeVerifier() {
	verifierPath := filepath.Join(p.storageDir, ".code_verifier")
	os.Remove(verifierPath)
}

// cleanupStaleCodeVerifier removes any expired code verifier from previous runs
func (p *OneDriveProvider) cleanupStaleCodeVerifier() {
	verifierPath := filepath.Join(p.storageDir, ".code_verifier")
	stat, err := os.Stat(verifierPath)
	if err != nil {
		return // File doesn't exist
	}
	if time.Since(stat.ModTime()) > codeVerifierMaxAge {
		os.Remove(verifierPath)
		log.Printf("OneDrive: cleaned up stale code verifier")
	}
}

// ============ PKCE HELPERS ============

func generateCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64URLEncode(bytes), nil
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64URLEncode(hash[:])
}

func base64URLEncode(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	encoded = strings.TrimRight(encoded, "=")
	return encoded
}
