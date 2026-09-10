package session

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrSessionNotFound is returned when a session ID does not exist or has been removed.
	ErrSessionNotFound = errors.New("session: session not found")
	// ErrSessionExpired is returned when a session has expired.
	ErrSessionExpired = errors.New("session: session expired")
	// ErrInvalidToken is returned when the session token format or length is invalid.
	ErrInvalidToken = errors.New("session: invalid session token")
)

// Session represents a user session containing session ID, user ID, data map, creation time, and expiration time.
type Session struct {
	ID        string
	UserID    string
	Data      map[string]any
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store defines the interface for session storage.
type Store interface {
	Create(ctx context.Context, userID string, ttl time.Duration, data map[string]any) (*Session, string, error)
	Get(ctx context.Context, token string) (*Session, error)
	Refresh(ctx context.Context, token string, ttl time.Duration) (*Session, error)
	Delete(ctx context.Context, token string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	Close() error
}

// MemoryStore implements Store using an in-memory concurrent-safe map with background cleanup.
type MemoryStore struct {
	mu            sync.RWMutex
	sessions      map[string]*Session // keyed by token hash or token
	tokens        map[string]string   // token -> sessionID (or direct storage)
	tokenBytes    int
	cleanupTicker *time.Ticker
	doneChan      chan struct{}
	closed        bool
}

// Option configures MemoryStore.
type Option func(*MemoryStore)

// WithTokenBytes sets the number of random bytes used for session tokens (default 32 bytes = 256 bits).
func WithTokenBytes(n int) Option {
	return func(s *MemoryStore) {
		if n > 0 {
			s.tokenBytes = n
		}
	}
}

// NewMemoryStore creates a new in-memory session store with background expiration cleanup.
func NewMemoryStore(cleanupInterval time.Duration, opts ...Option) *MemoryStore {
	store := &MemoryStore{
		sessions:   make(map[string]*Session),
		tokenBytes: 32,
		doneChan:   make(chan struct{}),
	}
	for _, opt := range opts {
		opt(store)
	}

	if cleanupInterval > 0 {
		store.cleanupTicker = time.NewTicker(cleanupInterval)
		go store.backgroundCleanup()
	}

	return store
}

// generateToken generates a CSPRNG cryptographically secure random token hex-encoded.
func (s *MemoryStore) generateToken() (string, error) {
	b := make([]byte, s.tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: failed to generate random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Create generates a new session for the given userID with a TTL and optional initial data.
func (s *MemoryStore) Create(ctx context.Context, userID string, ttl time.Duration, data map[string]any) (*Session, string, error) {
	if ctx.Err() != nil {
		return nil, "", ctx.Err()
	}
	token, err := s.generateToken()
	if err != nil {
		return nil, "", err
	}

	now := time.Now()
	expiresAt := now.Add(ttl)
	if ttl <= 0 {
		expiresAt = now.Add(24 * time.Hour) // default 24h if ttl <= 0
	}

	sessionData := make(map[string]any)
	for k, v := range data {
		sessionData[k] = v
	}

	sess := &Session{
		ID:        token, // Using token as session ID or keeping them identical for simplicity & security
		UserID:    userID,
		Data:      sessionData,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, "", errors.New("session: store is closed")
	}

	s.sessions[token] = sess

	// Return a copy of session to prevent race conditions on Data map mutation by caller.
	return cloneSession(sess), token, nil
}

// Get retrieves a session by its token, validating expiration and constant-time token comparison semantics.
func (s *MemoryStore) Get(ctx context.Context, token string) (*Session, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if token == "" {
		return nil, ErrInvalidToken
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, errors.New("session: store is closed")
	}

	// Constant-time lookup across keys to prevent timing attacks
	var matchedSession *Session
	for storedToken, sess := range s.sessions {
		if subtle.ConstantTimeCompare([]byte(storedToken), []byte(token)) == 1 {
			matchedSession = sess
			break
		}
	}

	if matchedSession == nil {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(matchedSession.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return cloneSession(matchedSession), nil
}

// Refresh extends a session's expiration time by ttl.
func (s *MemoryStore) Refresh(ctx context.Context, token string, ttl time.Duration) (*Session, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if token == "" {
		return nil, ErrInvalidToken
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, errors.New("session: store is closed")
	}

	var matchedToken string
	var matchedSession *Session
	for storedToken, sess := range s.sessions {
		if subtle.ConstantTimeCompare([]byte(storedToken), []byte(token)) == 1 {
			matchedToken = storedToken
			matchedSession = sess
			break
		}
	}

	if matchedSession == nil {
		return nil, ErrSessionNotFound
	}

	now := time.Now()
	if now.After(matchedSession.ExpiresAt) {
		delete(s.sessions, matchedToken)
		return nil, ErrSessionExpired
	}

	if ttl > 0 {
		matchedSession.ExpiresAt = now.Add(ttl)
	}

	return cloneSession(matchedSession), nil
}

// Delete removes a session by its token.
func (s *MemoryStore) Delete(ctx context.Context, token string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if token == "" {
		return ErrInvalidToken
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("session: store is closed")
	}

	var matchedToken string
	for storedToken := range s.sessions {
		if subtle.ConstantTimeCompare([]byte(storedToken), []byte(token)) == 1 {
			matchedToken = storedToken
			break
		}
	}

	if matchedToken == "" {
		return ErrSessionNotFound
	}

	delete(s.sessions, matchedToken)
	return nil
}

// DeleteUserSessions removes all sessions associated with a given userID.
func (s *MemoryStore) DeleteUserSessions(ctx context.Context, userID string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("session: store is closed")
	}

	for token, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, token)
		}
	}

	return nil
}

// Close stops the background cleanup ticker and closes the store.
func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if s.cleanupTicker != nil {
		s.cleanupTicker.Stop()
		close(s.doneChan)
	}

	// Clear sessions
	s.sessions = nil
	return nil
}

// backgroundCleanup periodically removes expired sessions.
func (s *MemoryStore) backgroundCleanup() {
	for {
		select {
		case <-s.cleanupTicker.C:
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				return
			}
			now := time.Now()
			for token, sess := range s.sessions {
				if now.After(sess.ExpiresAt) {
					delete(s.sessions, token)
				}
			}
			s.mu.Unlock()
		case <-s.doneChan:
			return
		}
	}
}

// cloneSession creates a deep copy of a Session object.
func cloneSession(src *Session) *Session {
	if src == nil {
		return nil
	}
	dataCopy := make(map[string]any, len(src.Data))
	for k, v := range src.Data {
		dataCopy[k] = v
	}
	return &Session{
		ID:        src.ID,
		UserID:    src.UserID,
		Data:      dataCopy,
		CreatedAt: src.CreatedAt,
		ExpiresAt: src.ExpiresAt,
	}
}
