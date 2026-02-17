package oauthstate

import (
	"sync"
	"time"
)

// StateEntry holds OAuth state and PKCE code verifier for a pending auth flow.
type StateEntry struct {
	State        string
	CodeVerifier string
	CreatedAt    time.Time
}

// Store is an in-memory store for OAuth state keyed by "sessionID:providerID".
type Store struct {
	mu      sync.Mutex
	entries map[string]*StateEntry
	ttl     time.Duration
	done    chan struct{}
}

// NewStore creates a new Store that evicts entries older than ttl.
// A background goroutine runs cleanup every minute. Call Close() to stop it.
func NewStore(ttl time.Duration) *Store {
	s := &Store{
		entries: make(map[string]*StateEntry),
		ttl:     ttl,
		done:    make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Close stops the background cleanup goroutine.
func (s *Store) Close() {
	close(s.done)
}

func key(sessionID, providerID string) string {
	return sessionID + ":" + providerID
}

// Put stores a state entry for the given session and provider.
func (s *Store) Put(sessionID, providerID string, entry *StateEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key(sessionID, providerID)] = entry
}

// Get retrieves the state entry for the given session and provider.
func (s *Store) Get(sessionID, providerID string) (*StateEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key(sessionID, providerID)]
	return e, ok
}

// Delete removes the state entry for the given session and provider.
func (s *Store) Delete(sessionID, providerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key(sessionID, providerID))
}

func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.done:
			return
		}
	}
}

func (s *Store) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, e := range s.entries {
		if now.Sub(e.CreatedAt) > s.ttl {
			delete(s.entries, k)
		}
	}
}

// Len returns the number of entries (for testing).
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// CleanupNow runs cleanup immediately (for testing).
func (s *Store) CleanupNow() {
	s.cleanup()
}
