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
	defaultMaxSessions         = 4
	defaultMaxAbsoluteLifetime = 30 * time.Minute
	defaultSessionTimeout      = 3 * time.Minute
	defaultBcryptCost          = 10 // bcrypt.DefaultCost
	sessionCookieName          = "pwsafe_session_id"
	passwordHashFile           = ".password_hash"
)

// dummyHash is used for timing-safe login when no password hash exists
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-safe-dummy"), bcrypt.DefaultCost)

// Session represents an active user session
type Session struct {
	ExpiresAt time.Time
	CreatedAt time.Time
	IP        string
}

// AuthService manages authentication and sessions
type AuthService struct {
	mu                  sync.Mutex
	sessions            map[string]*Session
	sessionTimeout      time.Duration
	bcryptCost          int
	maxSessions         int
	maxAbsoluteLifetime time.Duration
	dataDir             string
	configDir           string
	settings            *config.Settings
}

// NewAuthService creates a new AuthService
func NewAuthService(dataDir, configDir string, settings *config.Settings) *AuthService {
	timeout := defaultSessionTimeout
	cost := defaultBcryptCost
	maxSess := defaultMaxSessions
	maxLifetime := defaultMaxAbsoluteLifetime

	if settings.Auth != nil {
		if settings.Auth.SessionTimeout != "" {
			parsed, err := time.ParseDuration(settings.Auth.SessionTimeout)
			if err == nil {
				timeout = parsed
			} else {
				log.Printf("Warning: invalid sessionTimeout %q, using default %s", settings.Auth.SessionTimeout, defaultSessionTimeout)
			}
		}

		if settings.Auth.BcryptCost != 0 {
			if settings.Auth.BcryptCost >= 4 && settings.Auth.BcryptCost <= 14 {
				cost = settings.Auth.BcryptCost
			} else {
				log.Printf("Warning: invalid bcryptCost %d (must be 4-14), using default %d", settings.Auth.BcryptCost, defaultBcryptCost)
			}
		}

		if settings.Auth.MaxSessions != 0 {
			if settings.Auth.MaxSessions >= 1 && settings.Auth.MaxSessions <= 10000 {
				maxSess = settings.Auth.MaxSessions
			} else {
				log.Printf("Warning: invalid maxSessions %d (must be 1-10000), using default %d", settings.Auth.MaxSessions, defaultMaxSessions)
			}
		}

		if settings.Auth.MaxSessionLifetime != "" {
			parsed, err := time.ParseDuration(settings.Auth.MaxSessionLifetime)
			if err == nil {
				if parsed >= 1*time.Minute {
					maxLifetime = parsed
				} else {
					log.Printf("Warning: maxSessionLifetime %s is below minimum 1m, using default %s", settings.Auth.MaxSessionLifetime, defaultMaxAbsoluteLifetime)
				}
			} else {
				log.Printf("Warning: invalid maxSessionLifetime %q, using default %s", settings.Auth.MaxSessionLifetime, defaultMaxAbsoluteLifetime)
			}
		}

		if timeout > maxLifetime {
			log.Printf("Warning: sessionTimeout %s exceeds maxSessionLifetime %s, capping", timeout, maxLifetime)
			timeout = maxLifetime
		}
	}

	return &AuthService{
		sessions:            make(map[string]*Session),
		sessionTimeout:      timeout,
		bcryptCost:          cost,
		maxSessions:         maxSess,
		maxAbsoluteLifetime: maxLifetime,
		dataDir:             dataDir,
		configDir:           configDir,
		settings:            settings,
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

	if mode != "disabled" && mode != "enabled" {
		return fmt.Errorf("invalid mode: %s", mode)
	}

	if mode == "enabled" {
		if password == "" {
			return fmt.Errorf("password required when auth mode is enabled")
		}
		if len(password) > 72 {
			password = password[:72]
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
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
		if mode == "enabled" {
			os.Remove(filepath.Join(s.dataDir, passwordHashFile))
		}
		return fmt.Errorf("failed to save settings: %w", err)
	}

	return nil
}

// Login verifies password and creates a session
func (s *AuthService) Login(password string, ip string) (string, error) {
	if len(password) > 72 {
		password = password[:72]
	}

	hashPath := filepath.Join(s.dataDir, passwordHashFile)
	hash, err := os.ReadFile(hashPath)
	if err != nil {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
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
	if len(s.sessions) >= s.maxSessions {
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
	sessionIDBytes := make([]byte, 16) // 128 bits
	if _, err := io.ReadFull(rand.Reader, sessionIDBytes); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	sessionID := hex.EncodeToString(sessionIDBytes)

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
	if now.After(sess.ExpiresAt) || now.Sub(sess.CreatedAt) > s.maxAbsoluteLifetime {
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
	if now.After(sess.ExpiresAt) || now.Sub(sess.CreatedAt) > s.maxAbsoluteLifetime {
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
				if now.After(sess.ExpiresAt) || now.Sub(sess.CreatedAt) > s.maxAbsoluteLifetime {
					delete(s.sessions, id)
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

// ClearAllSessions removes all active sessions
func (s *AuthService) ClearAllSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]*Session)
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

// GetBcryptCost returns the bcrypt cost (for testing)
func (s *AuthService) GetBcryptCost() int {
	return s.bcryptCost
}

// GetMaxSessions returns the max sessions (for testing)
func (s *AuthService) GetMaxSessions() int {
	return s.maxSessions
}

// GetMaxAbsoluteLifetime returns the max absolute session lifetime (for testing)
func (s *AuthService) GetMaxAbsoluteLifetime() time.Duration {
	return s.maxAbsoluteLifetime
}
