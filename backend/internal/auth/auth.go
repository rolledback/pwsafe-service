package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/rolledback/pwsafe-service/backend/internal/config"
)

const (
	maxSessions           = 100
	maxAbsoluteLifetime   = 24 * time.Hour
	defaultSessionTimeout = 3 * time.Minute
	banThreshold          = 5
	banWindow             = 15 * time.Minute
	banDuration           = 1 * time.Hour
	sessionCookieName     = "pwsafe_session"
	passwordHashFile      = ".password_hash"
)

// Session represents an active user session
type Session struct {
	ExpiresAt time.Time
	CreatedAt time.Time
	IP        string
}

type rateLimitHit struct {
	timestamps []time.Time
}

type ipBan struct {
	expiresAt    time.Time
	lastLogTime  time.Time
}

// AuthService manages authentication, sessions, and IP banning
type AuthService struct {
	mu             sync.Mutex
	sessions       map[string]*Session
	ipBans         map[string]*ipBan
	rateLimitHits  map[string]*rateLimitHit
	sessionTimeout time.Duration
	dataDir        string
	configDir      string
	settings       *config.Settings
}

// NewAuthService creates a new AuthService
func NewAuthService(dataDir, configDir string, settings *config.Settings) *AuthService {
	timeout := defaultSessionTimeout
	if settings.Auth != nil && settings.Auth.SessionTimeout != "" {
		parsed, err := time.ParseDuration(settings.Auth.SessionTimeout)
		if err == nil {
			timeout = parsed
		} else {
			log.Printf("Warning: invalid sessionTimeout %q, using default %s", settings.Auth.SessionTimeout, defaultSessionTimeout)
		}
	}

	return &AuthService{
		sessions:       make(map[string]*Session),
		ipBans:         make(map[string]*ipBan),
		rateLimitHits:  make(map[string]*rateLimitHit),
		sessionTimeout: timeout,
		dataDir:        dataDir,
		configDir:      configDir,
		settings:       settings,
	}
}

// GetMode returns the current auth mode
func (s *AuthService) GetMode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settings.Auth == nil || s.settings.Auth.Mode == "" {
		return "unset"
	}
	return s.settings.Auth.Mode
}

// Setup configures the auth mode and optionally sets a password
func (s *AuthService) Setup(mode string, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.settings.Auth != nil && s.settings.Auth.Mode != "" {
		return fmt.Errorf("auth mode already configured")
	}

	if mode != "unsecured" && mode != "secured" {
		return fmt.Errorf("invalid mode: %s", mode)
	}

	if mode == "secured" {
		if password == "" {
			return fmt.Errorf("password required for secured mode")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		hashPath := filepath.Join(s.dataDir, passwordHashFile)
		if err := os.WriteFile(hashPath, hash, 0600); err != nil {
			return fmt.Errorf("failed to write password hash: %w", err)
		}
	}

	if s.settings.Auth == nil {
		s.settings.Auth = &config.AuthConfig{}
	}
	s.settings.Auth.Mode = mode

	if err := config.SaveSettings(s.configDir, s.settings); err != nil {
		// Rollback mode on save failure
		s.settings.Auth.Mode = ""
		// Clean up hash file if it was written
		if mode == "secured" {
			os.Remove(filepath.Join(s.dataDir, passwordHashFile))
		}
		return fmt.Errorf("failed to save settings: %w", err)
	}

	return nil
}

// Login verifies password and creates a session
func (s *AuthService) Login(password string, ip string) (string, error) {
	hashPath := filepath.Join(s.dataDir, passwordHashFile)
	hash, err := os.ReadFile(hashPath)
	if err != nil {
		return "", fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		return "", fmt.Errorf("invalid credentials")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Invalidate previous sessions from same IP
	for id, sess := range s.sessions {
		if sess.IP == ip {
			delete(s.sessions, id)
		}
	}

	// Enforce max session cap
	if len(s.sessions) >= maxSessions {
		// Evict oldest session
		var oldestID string
		var oldestTime time.Time
		for id, sess := range s.sessions {
			if oldestID == "" || sess.CreatedAt.Before(oldestTime) {
				oldestID = id
				oldestTime = sess.CreatedAt
			}
		}
		if oldestID != "" {
			delete(s.sessions, oldestID)
		}
	}

	// Generate session ID
	tokenBytes := make([]byte, 16) // 128 bits
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	sessionID := hex.EncodeToString(tokenBytes)

	now := time.Now()
	s.sessions[sessionID] = &Session{
		ExpiresAt: now.Add(s.sessionTimeout),
		CreatedAt: now,
		IP:        ip,
	}

	return sessionID, nil
}

// ValidateSession checks if a session is valid and extends its timeout
func (s *AuthService) ValidateSession(sessionID string, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return false
	}

	now := time.Now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.CreatedAt) > maxAbsoluteLifetime {
		delete(s.sessions, sessionID)
		return false
	}

	// Reject if request IP doesn't match session IP
	if sess.IP != ip {
		return false
	}

	// Extend inactivity timeout
	sess.ExpiresAt = now.Add(s.sessionTimeout)
	return true
}

// IsAuthenticated checks session validity without extending it
func (s *AuthService) IsAuthenticated(sessionID string, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return false
	}

	now := time.Now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.CreatedAt) > maxAbsoluteLifetime {
		delete(s.sessions, sessionID)
		return false
	}

	// Reject if request IP doesn't match session IP
	if sess.IP != ip {
		return false
	}

	return true
}

// Logout removes a session
func (s *AuthService) Logout(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// IsIPBanned checks if an IP is currently banned
func (s *AuthService) IsIPBanned(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	ban, ok := s.ipBans[ip]
	if !ok {
		return false
	}
	now := time.Now()
	if now.After(ban.expiresAt) {
		delete(s.ipBans, ip)
		return false
	}
	
	// Log throttling: only log once per minute
	if now.Sub(ban.lastLogTime) >= 1*time.Minute {
		log.Printf("IP banned: %s (blocked request)", ip)
		ban.lastLogTime = now
	}
	return true
}

// RecordRateLimitHit records a rate limit hit for an IP and bans after threshold
func (s *AuthService) RecordRateLimitHit(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hits, ok := s.rateLimitHits[ip]
	if !ok {
		hits = &rateLimitHit{}
		s.rateLimitHits[ip] = hits
	}

	now := time.Now()
	cutoff := now.Add(-banWindow)

	// Prune old hits
	fresh := make([]time.Time, 0, len(hits.timestamps))
	for _, t := range hits.timestamps {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	hits.timestamps = append(fresh, now)

	if len(hits.timestamps) >= banThreshold {
		s.ipBans[ip] = &ipBan{
			expiresAt:   now.Add(banDuration),
			lastLogTime: now,
		}
		log.Printf("IP banned: %s (exceeded rate limit threshold)", ip)
		delete(s.rateLimitHits, ip)
	}
}

// CleanupExpiredSessions removes expired sessions periodically
func (s *AuthService) CleanupExpiredSessions(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for id, sess := range s.sessions {
				if now.After(sess.ExpiresAt) || now.Sub(sess.CreatedAt) > maxAbsoluteLifetime {
					delete(s.sessions, id)
				}
			}
			// Clean expired bans
			for ip, ban := range s.ipBans {
				if now.After(ban.expiresAt) {
					delete(s.ipBans, ip)
				}
			}
			// Clean old rate limit hits
			cutoff := now.Add(-banWindow)
			for ip, hits := range s.rateLimitHits {
				fresh := hits.timestamps[:0]
				for _, t := range hits.timestamps {
					if t.After(cutoff) {
						fresh = append(fresh, t)
					}
				}
				if len(fresh) == 0 {
					delete(s.rateLimitHits, ip)
				} else {
					hits.timestamps = fresh
				}
			}
			s.mu.Unlock()
		}
	}
}

// SetSessionCookie sets the session cookie on the response
func SetSessionCookie(w http.ResponseWriter, sessionID string, secure bool, timeout time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(timeout.Seconds()),
	})
}

// ClearSessionCookie clears the session cookie
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetSessionIDFromRequest reads the session ID from the request cookie
func GetSessionIDFromRequest(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	// Validate cookie format: must be valid hex and expected length (32 hex chars = 16 bytes)
	if len(cookie.Value) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(cookie.Value); err != nil {
		return ""
	}
	return cookie.Value
}

// SessionCount returns the number of active sessions (for testing)
func (s *AuthService) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// GetSessionTimeout returns the session timeout (for testing)
func (s *AuthService) GetSessionTimeout() time.Duration {
	return s.sessionTimeout
}
