package oauth

import (
	"context"
	"errors"
	"time"
)

// Error sentinels for OAuth2 grant flows.
var (
	// ErrInvalidGrant is returned when the grant type or request is malformed.
	ErrInvalidGrant = errors.New("oauth: invalid grant")
	// ErrInvalidCredentials is returned when password verification fails.
	ErrInvalidCredentials = errors.New("oauth: invalid credentials")
	// ErrInvalidPKCE is returned when PKCE verification fails.
	ErrInvalidPKCE = errors.New("oauth: invalid PKCE")
	// ErrExpiredToken is returned when a token or code has expired.
	ErrExpiredToken = errors.New("oauth: token expired")
	// ErrTokenRevoked is returned when a token has been revoked.
	ErrTokenRevoked = errors.New("oauth: token revoked")
	// ErrTokenReuseDetected is returned when a revoked refresh token is
	// presented again, indicating token reuse. The token family is
	// revoked as a defensive measure.
	ErrTokenReuseDetected = errors.New("oauth: token reuse detected")
	// ErrInvalidRedirectURI is returned when the redirect URI does not
	// match the one bound to the authorization code.
	ErrInvalidRedirectURI = errors.New("oauth: invalid redirect URI")
)

// RefreshToken represents a stored refresh token with rotation state.
// The TokenHash is the SHA-256 hash of the raw token — never store the
// raw token. FamilyID groups a chain of rotated tokens; revoking a
// family invalidates all tokens in the chain.
type RefreshToken struct {
	ID        string
	UserID    string
	FamilyID  string
	TokenHash string
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// RefreshTokenStore defines the storage interface for refresh tokens.
// Implementations are provided by consumers — trust is stateless and
// does not ship a default implementation.
type RefreshTokenStore interface {
	// Create stores a new refresh token record.
	Create(ctx context.Context, token *RefreshToken) error
	// GetByHash retrieves a refresh token by its SHA-256 hash.
	GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	// MarkRevoked marks a token as revoked at the given time. Used during
	// normal rotation (old token revoked, new token issued).
	MarkRevoked(ctx context.Context, tokenID string, revokedAt time.Time) error
	// RevokeFamily revokes all tokens in a family. Used when token reuse
	// is detected — the entire chain is invalidated as a defensive measure.
	RevokeFamily(ctx context.Context, familyID string) error
}

// AuthCode represents a stored authorization code with PKCE binding.
// The CodeHash is the SHA-256 hash of the raw code — never store the
// raw code. CodeChallenge and CodeChallengeMethod bind the code to a
// PKCE verifier for the token exchange.
type AuthCode struct {
	ID                  string
	UserID              string
	CodeHash            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	ConsumedAt          *time.Time
}

// AuthCodeStore defines the storage interface for authorization codes.
// Implementations are provided by consumers — trust is stateless.
type AuthCodeStore interface {
	// Create stores a new authorization code record.
	Create(ctx context.Context, code *AuthCode) error
	// GetByHash retrieves an authorization code by its SHA-256 hash.
	GetByHash(ctx context.Context, codeHash string) (*AuthCode, error)
	// MarkConsumed marks a code as consumed at the given time.
	// Authorization codes are single-use — a consumed code cannot be
	// exchanged again.
	MarkConsumed(ctx context.Context, codeID string, consumedAt time.Time) error
}
