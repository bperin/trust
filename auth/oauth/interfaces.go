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
	// ErrInvalidClient is returned when an authorization code is presented
	// by a client other than the one it was issued to ([RFC 6749] §4.1.3).
	ErrInvalidClient = errors.New("oauth: invalid client")
	// ErrInvalidPKCE is returned when PKCE verification fails.
	ErrInvalidPKCE = errors.New("oauth: invalid PKCE")
	// ErrExpiredToken is returned when a token or code has expired.
	ErrExpiredToken = errors.New("oauth: token expired")
	// ErrTokenRevoked is returned when a token has been revoked.
	// RefreshTokenStore.Revoke returns this sentinel when the token was
	// already revoked, signalling refresh-token reuse to the caller.
	ErrTokenRevoked = errors.New("oauth: token revoked")
	// ErrTokenReuseDetected is returned when a revoked refresh token is
	// presented again, indicating token reuse. The token family is
	// revoked as a defensive measure.
	ErrTokenReuseDetected = errors.New("oauth: token reuse detected")
	// ErrCodeConsumed is returned by AuthCodeStore.Consume when the
	// authorization code was already consumed. Authorization codes are
	// single-use per [RFC 6749] §4.1.2.
	ErrCodeConsumed = errors.New("oauth: authorization code already consumed")
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
	// Revoke atomically marks a token as revoked at the given time, but
	// only when it is not already revoked. Used during refresh-token
	// rotation — the check-and-set MUST be atomic (a single conditional
	// UPDATE, a compare-and-swap, or a mutex for in-memory stores) so that
	// two concurrent requests cannot both consume the same token. Revoke
	// returns ErrTokenRevoked when the token was already revoked; grant
	// code treats that as token reuse and revokes the family.
	Revoke(ctx context.Context, tokenID string, revokedAt time.Time) error
	// RevokeFamily revokes all tokens in a family. Used when token reuse
	// is detected — the entire chain is invalidated as a defensive measure.
	RevokeFamily(ctx context.Context, familyID string) error
}

// AuthCode represents a stored authorization code with PKCE and client
// binding. The CodeHash is the SHA-256 hash of the raw code — never
// store the raw code. ClientID binds the code to the client that
// initiated the authorization flow per [RFC 6749] §4.1.3 — the code can
// only be redeemed by that client. CodeChallenge and CodeChallengeMethod
// bind the code to a PKCE verifier for the token exchange.
type AuthCode struct {
	ID                  string
	UserID              string
	ClientID            string
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
	// Consume atomically marks a code as consumed at the given time, but
	// only when it is not already consumed. Authorization codes are
	// single-use per [RFC 6749] §4.1.2 — the check-and-set MUST be atomic
	// (a single conditional UPDATE, a compare-and-swap, or a mutex for
	// in-memory stores) so that concurrent redemption of the same code
	// succeeds at most once. Consume returns ErrCodeConsumed when the
	// code was already consumed.
	Consume(ctx context.Context, codeID string, consumedAt time.Time) error
}
