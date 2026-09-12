package session

import (
	"context"
	"errors"
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

// Session represents a user session containing session ID, user ID, data
// map, creation time, and expiration time.
type Session struct {
	ID        string
	UserID    string
	Data      map[string]any
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store defines the interface for session storage. Implementations are
// provided by consumers — trust is stateless and does not ship a
// default implementation.
type Store interface {
	Create(ctx context.Context, userID string, ttl time.Duration, data map[string]any) (*Session, string, error)
	Get(ctx context.Context, token string) (*Session, error)
	Refresh(ctx context.Context, token string, ttl time.Duration) (*Session, error)
	Delete(ctx context.Context, token string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	Close() error
}
