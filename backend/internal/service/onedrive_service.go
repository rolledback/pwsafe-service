package service

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

	"github.com/rolledback/pwsafe-service/backend/internal/models"
)

const (
	msAuthority        = "https://login.microsoftonline.com/consumers"
	msAuthorizeURL     = msAuthority + "/oauth2/v2.0/authorize"
	msTokenURL         = msAuthority + "/oauth2/v2.0/token"
	msGraphURL         = "https://graph.microsoft.com/v1.0"
	onedriveScopes     = "Files.Read User.Read offline_access"
	syncInterval       = 15 * time.Minute
	codeVerifierMaxAge = 15 * time.Minute
)

type OneDriveService struct {
	safesDirectory string
	clientID       string
	redirectURI    string
	codeVerifier   string
	tokenMutex     sync.Mutex
	syncMutex      sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	nextTickAt     time.Time
	nextTickMutex  sync.Mutex
}

func NewOneDriveService(ctx context.Context, safesDirectory, clientID, redirectURI string) *OneDriveService {
	ctx, cancel := context.WithCancel(ctx)
	s := &OneDriveService{
		safesDirectory: safesDirectory,
		clientID:       clientID,
		redirectURI:    redirectURI,
		ctx:            ctx,
		cancel:         cancel,
		nextTickAt:     time.Now().Add(syncInterval),
	}
	// Clean up any stale code verifier from previous runs
	if _, err := s.loadCodeVerifier(); err != nil && err.Error() == "code verifier expired" {
		log.Printf("OneDrive: cleaned up stale code verifier")
	}
	go s.periodicSync()
	return s
}

// Stop stops the background sync goroutine
func (s *OneDriveService) Stop() {
	s.cancel()
}

func (s *OneDriveService) periodicSync() {
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("OneDrive: periodic sync stopped")
			return
		case <-ticker.C:
			s.tryPeriodicSync()

			// Update next tick time after sync completes
			s.nextTickMutex.Lock()
			s.nextTickAt = time.Now().Add(syncInterval)
			s.nextTickMutex.Unlock()
		}
	}
}

func (s *OneDriveService) tryPeriodicSync() {
	// Check if we're connected (have valid/refreshable token)
	_, err := s.getValidAccessToken()
	if err != nil {
		log.Printf("OneDrive: skipping periodic sync (not connected)")
		return
	}

	log.Printf("OneDrive: starting periodic sync")
	_, err = s.Sync()
	if err != nil {
		log.Printf("OneDrive: periodic sync failed: %v", err)
	} else {
		log.Printf("OneDrive: periodic sync completed")
	}
}

func (s *OneDriveService) tokensFilePath() string {
	return filepath.Join(s.safesDirectory, "onedrive", ".tokens.json")
}

func (s *OneDriveService) GetStatus() (*models.OneDriveStatus, error) {
	// Wait for any in-progress sync to complete (read lock waits for write lock to release)
	s.syncMutex.RLock()
	defer s.syncMutex.RUnlock()

	status := &models.OneDriveStatus{
		Connected:   false,
		NeedsReauth: false,
	}

	tokensPath := s.tokensFilePath()
	data, err := os.ReadFile(tokensPath)
	if err != nil {
		if os.IsNotExist(err) {
			return status, nil
		}
		return nil, fmt.Errorf("failed to read tokens file: %w", err)
	}

	var tokens models.OneDriveTokens
	if err := json.Unmarshal(data, &tokens); err != nil {
		return status, nil
	}

	// Check if tokens exist
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		return status, nil
	}

	// Check if token is expired
	expiresAt, err := time.Parse(time.RFC3339, tokens.ExpiresAt)
	if err != nil {
		status.NeedsReauth = true
		return status, nil
	}

	if time.Now().After(expiresAt) {
		// Token expired, but we have refresh token - auto-refresh will handle it
		// NeedsReauth stays false since we can refresh
		status.Connected = true
	} else {
		status.Connected = true
	}

	status.AccountName = tokens.AccountName
	status.AccountEmail = tokens.AccountEmail

	// Load lastSyncTime from config and calculate nextSyncAt
	config, err := s.loadConfig()
	if err == nil && config.LastSyncTime != "" {
		status.LastSyncTime = config.LastSyncTime
	}

	// Get next tick time from the actual ticker
	s.nextTickMutex.Lock()
	status.NextSyncAt = s.nextTickAt.Format(time.RFC3339)
	s.nextTickMutex.Unlock()

	return status, nil
}

func (s *OneDriveService) GetAuthURL() (*models.OneDriveAuthURL, error) {
	if s.clientID == "" {
		return nil, fmt.Errorf("ONEDRIVE_CLIENT_ID not configured")
	}

	// Generate PKCE code verifier and challenge
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}
	s.codeVerifier = codeVerifier

	codeChallenge := generateCodeChallenge(codeVerifier)

	// Store code verifier for later use in callback
	if err := s.storeCodeVerifier(codeVerifier); err != nil {
		return nil, fmt.Errorf("failed to store code verifier: %w", err)
	}

	params := url.Values{
		"client_id":             {s.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {s.redirectURI},
		"scope":                 {onedriveScopes},
		"response_mode":         {"query"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	authURL := msAuthorizeURL + "?" + params.Encode()

	return &models.OneDriveAuthURL{URL: authURL}, nil
}

func (s *OneDriveService) HandleCallback(code string) error {
	if s.clientID == "" {
		return fmt.Errorf("ONEDRIVE_CLIENT_ID not configured")
	}

	// Retrieve code verifier
	codeVerifier, err := s.loadCodeVerifier()
	if err != nil {
		return fmt.Errorf("failed to load code verifier: %w", err)
	}

	// Exchange code for tokens
	tokens, err := s.exchangeCodeForTokens(code, codeVerifier)
	if err != nil {
		return fmt.Errorf("failed to exchange code for tokens: %w", err)
	}

	// Get user profile
	accountName, accountEmail, err := s.getUserProfile(tokens.AccessToken)
	if err != nil {
		// Non-fatal: continue without profile info
		accountName = ""
		accountEmail = ""
	}
	tokens.AccountName = accountName
	tokens.AccountEmail = accountEmail

	// Store tokens
	if err := s.storeTokens(tokens); err != nil {
		return fmt.Errorf("failed to store tokens: %w", err)
	}

	// Clean up code verifier
	s.deleteCodeVerifier()

	return nil
}

func (s *OneDriveService) exchangeCodeForTokens(code, codeVerifier string) (*models.OneDriveTokens, error) {
	data := url.Values{
		"client_id":     {s.clientID},
		"code":          {code},
		"redirect_uri":  {s.redirectURI},
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

	return &models.OneDriveTokens{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
	}, nil
}

func (s *OneDriveService) getUserProfile(accessToken string) (name, email string, err error) {
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

func (s *OneDriveService) storeTokens(tokens *models.OneDriveTokens) error {
	// Ensure onedrive directory exists
	onedriveDir := filepath.Join(s.safesDirectory, "onedrive")
	if err := os.MkdirAll(onedriveDir, 0700); err != nil {
		return fmt.Errorf("failed to create onedrive directory: %w", err)
	}

	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}

	tokensPath := s.tokensFilePath()
	if err := os.WriteFile(tokensPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write tokens file: %w", err)
	}

	return nil
}

func (s *OneDriveService) storeCodeVerifier(verifier string) error {
	onedriveDir := filepath.Join(s.safesDirectory, "onedrive")
	if err := os.MkdirAll(onedriveDir, 0700); err != nil {
		return err
	}

	verifierPath := filepath.Join(onedriveDir, ".code_verifier")
	return os.WriteFile(verifierPath, []byte(verifier), 0600)
}

func (s *OneDriveService) loadCodeVerifier() (string, error) {
	verifierPath := filepath.Join(s.safesDirectory, "onedrive", ".code_verifier")

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

func (s *OneDriveService) deleteCodeVerifier() {
	verifierPath := filepath.Join(s.safesDirectory, "onedrive", ".code_verifier")
	os.Remove(verifierPath)
}

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

func (s *OneDriveService) configFilePath() string {
	return filepath.Join(s.safesDirectory, "onedrive", ".config.json")
}

func (s *OneDriveService) loadConfig() (*models.OneDriveConfig, error) {
	configPath := s.configFilePath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &models.OneDriveConfig{Files: []models.OneDriveFile{}}, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config models.OneDriveConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if config.Files == nil {
		config.Files = []models.OneDriveFile{}
	}

	return &config, nil
}

func (s *OneDriveService) saveConfig(config *models.OneDriveConfig) error {
	onedriveDir := filepath.Join(s.safesDirectory, "onedrive")
	if err := os.MkdirAll(onedriveDir, 0700); err != nil {
		return fmt.Errorf("failed to create onedrive directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	configPath := s.configFilePath()
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// refreshAccessTokenLocked refreshes the access token. Must be called while holding tokenMutex.
func (s *OneDriveService) refreshAccessTokenLocked(refreshToken, accountName, accountEmail string) (*models.OneDriveTokens, error) {
	log.Printf("OneDrive: refreshing access token...")

	if refreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	// Request new tokens using refresh token
	formData := url.Values{
		"client_id":     {s.clientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
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
		// Check for invalid_grant error (refresh token is dead)
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

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	// Microsoft may or may not return a new refresh token
	newRefreshToken := tokenResp.RefreshToken
	if newRefreshToken == "" {
		newRefreshToken = refreshToken
	}

	newTokens := &models.OneDriveTokens{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		AccountName:  accountName,
		AccountEmail: accountEmail,
	}

	// Store updated tokens
	if err := s.storeTokens(newTokens); err != nil {
		return nil, fmt.Errorf("failed to store refreshed tokens: %w", err)
	}

	log.Printf("OneDrive: access token refreshed successfully")
	return newTokens, nil
}

func (s *OneDriveService) getValidAccessToken() (string, error) {
	s.tokenMutex.Lock()
	defer s.tokenMutex.Unlock()

	tokensPath := s.tokensFilePath()
	data, err := os.ReadFile(tokensPath)
	if err != nil {
		return "", fmt.Errorf("no tokens found: %w", err)
	}

	var tokens models.OneDriveTokens
	if err := json.Unmarshal(data, &tokens); err != nil {
		return "", fmt.Errorf("failed to parse tokens: %w", err)
	}

	if tokens.AccessToken == "" {
		return "", fmt.Errorf("no access token")
	}

	expiresAt, err := time.Parse(time.RFC3339, tokens.ExpiresAt)
	if err != nil {
		return "", fmt.Errorf("invalid expiry time")
	}

	// If token is still valid, return it
	if time.Now().Before(expiresAt) {
		return tokens.AccessToken, nil
	}

	// Token expired - try to refresh
	if tokens.RefreshToken == "" {
		return "", fmt.Errorf("REAUTH_REQUIRED: token expired and no refresh token")
	}

	newTokens, err := s.refreshAccessTokenLocked(tokens.RefreshToken, tokens.AccountName, tokens.AccountEmail)
	if err != nil {
		return "", err
	}

	return newTokens.AccessToken, nil
}

func (s *OneDriveService) searchOneDriveFiles(accessToken string) ([]models.OneDriveFile, error) {
	searchURL := msGraphURL + "/me/drive/root/search(q='.psafe3')"
	req, err := http.NewRequest("GET", searchURL, nil)
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

	var files []models.OneDriveFile
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

		files = append(files, models.OneDriveFile{
			ID:       item.ID,
			Name:     item.Name,
			Path:     path,
			Selected: false,
		})
	}

	return files, nil
}

func (s *OneDriveService) ListFiles() (*models.OneDriveFilesResponse, error) {
	config, err := s.loadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Try to get valid access token
	accessToken, err := s.getValidAccessToken()
	if err != nil {
		// Token invalid/expired - return only saved config files
		return &models.OneDriveFilesResponse{Files: config.Files}, nil
	}

	// Search OneDrive for .psafe3 files
	oneDriveFiles, err := s.searchOneDriveFiles(accessToken)
	if err != nil {
		// Search failed - return only saved config files
		return &models.OneDriveFilesResponse{Files: config.Files}, nil
	}

	// Build a map of saved selections by ID
	savedSelections := make(map[string]bool)
	for _, f := range config.Files {
		savedSelections[f.ID] = f.Selected
	}

	// Merge with saved config (preserve selected state)
	for i := range oneDriveFiles {
		if selected, exists := savedSelections[oneDriveFiles[i].ID]; exists {
			oneDriveFiles[i].Selected = selected
		}
	}

	return &models.OneDriveFilesResponse{Files: oneDriveFiles}, nil
}

func (s *OneDriveService) SaveFiles(files []models.OneDriveFile) error {
	config, err := s.loadConfig()
	if err != nil {
		config = &models.OneDriveConfig{}
	}

	config.Files = files
	return s.saveConfig(config)
}

func (s *OneDriveService) Disconnect() error {
	onedriveDir := filepath.Join(s.safesDirectory, "onedrive")

	// Delete tokens file
	tokensPath := s.tokensFilePath()
	if err := os.Remove(tokensPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove tokens file: %w", err)
	}

	// Delete config file if exists
	configPath := filepath.Join(onedriveDir, ".config.json")
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file: %w", err)
	}

	// Delete code verifier if exists
	s.deleteCodeVerifier()

	// Delete all synced .psafe3 files in onedrive directory (recursively)
	if err := s.cleanupAllSafeFiles(onedriveDir); err != nil {
		return fmt.Errorf("failed to cleanup safe files: %w", err)
	}

	return nil
}

func (s *OneDriveService) cleanupAllSafeFiles(onedriveDir string) error {
	if _, err := os.Stat(onedriveDir); os.IsNotExist(err) {
		return nil
	}

	return filepath.WalkDir(onedriveDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".psafe3") {
			if os.Remove(path) == nil {
				cleanupEmptyParentDirs(filepath.Dir(path), onedriveDir)
			}
		}
		return nil
	})
}

func (s *OneDriveService) Sync() (*models.OneDriveSyncResponse, error) {
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()

	config, err := s.loadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	accessToken, err := s.getValidAccessToken()
	if err != nil {
		return nil, fmt.Errorf("not authenticated: %w", err)
	}

	// Get selected files
	selectedFiles := []models.OneDriveFile{}
	for _, f := range config.Files {
		if f.Selected {
			selectedFiles = append(selectedFiles, f)
		}
	}

	results := []models.OneDriveSyncResult{}
	onedriveDir := filepath.Join(s.safesDirectory, "onedrive")

	// Download each selected file
	for _, file := range selectedFiles {
		localPath := s.getLocalPath(file)
		result := models.OneDriveSyncResult{
			Name:    file.Name,
			Success: false,
		}

		lastModified, err := s.downloadFile(accessToken, file.ID, localPath)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
			result.LastModified = lastModified
		}
		results = append(results, result)
	}

	// Cleanup: delete local .psafe3 files that are no longer selected
	s.cleanupUnselectedFiles(onedriveDir, selectedFiles)

	// Update lastSyncTime
	config.LastSyncTime = time.Now().Format(time.RFC3339)
	if err := s.saveConfig(config); err != nil {
		return nil, fmt.Errorf("failed to save config: %w", err)
	}

	return &models.OneDriveSyncResponse{Results: results}, nil
}

func (s *OneDriveService) getLocalPath(file models.OneDriveFile) string {
	// Build path: /safes/onedrive/{onedrive-path}/{filename}
	onedriveDir := filepath.Join(s.safesDirectory, "onedrive")
	// file.Path is the parent folder path (e.g., "/Documents/Passwords")
	relativePath := filepath.FromSlash(file.Path)
	// Remove leading slash if present
	relativePath = strings.TrimPrefix(relativePath, string(filepath.Separator))
	return filepath.Join(onedriveDir, relativePath, file.Name)
}

func (s *OneDriveService) downloadFile(accessToken, fileID, localPath string) (string, error) {
	// Create parent directories
	dir := filepath.Dir(localPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	// Download from OneDrive
	downloadURL := fmt.Sprintf("%s/me/drive/items/%s/content", msGraphURL, fileID)
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Get last modified from response header
	lastModified := resp.Header.Get("Last-Modified")

	// Write to file
	file, err := os.Create(localPath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(file, resp.Body); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	return lastModified, nil
}

func (s *OneDriveService) cleanupUnselectedFiles(onedriveDir string, selectedFiles []models.OneDriveFile) {
	// Build a set of selected file paths
	selectedPaths := make(map[string]bool)
	for _, f := range selectedFiles {
		localPath := s.getLocalPath(f)
		selectedPaths[localPath] = true
	}

	// Walk through onedrive directory and delete unselected .psafe3 files
	filepath.WalkDir(onedriveDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		// Skip hidden files (config, tokens, etc.)
		if strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".psafe3") {
			if !selectedPaths[path] {
				if os.Remove(path) == nil {
					cleanupEmptyParentDirs(filepath.Dir(path), onedriveDir)
				}
			}
		}
		return nil
	})
}

func cleanupEmptyParentDirs(dir, baseDir string) {
	for dir != baseDir && len(dir) > len(baseDir) {
		if err := os.Remove(dir); err != nil {
			break // Stop if dir not empty or error
		}
		dir = filepath.Dir(dir)
	}
}
