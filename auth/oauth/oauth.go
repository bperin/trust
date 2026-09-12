package oauth

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/bperin/auth/claims"
	"github.com/bperin/auth/password"
	"github.com/bperin/auth/token"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rand"
)

// AlgorithmEdDSA is the JWS algorithm for Ed25519 signatures per
// [RFC 8037] §3.1.
const AlgorithmEdDSA = "EdDSA"

// GrantOptions configures token issuance for all grant flows. Consumers
// populate this with their issuer, audience, TTLs, signing key, and
// any custom claims (e.g. organization_id, scopes, roles).
type GrantOptions struct {
	// Issuer is the "iss" claim — identifies the token issuer.
	Issuer string
	// Audience is the "aud" claim — identifies the intended recipient.
	Audience string
	// AccessTokenTTL is the lifetime of the access token.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is the lifetime of the refresh token.
	RefreshTokenTTL time.Duration
	// Extra contains custom claims to include in the access token JWT.
	// Consumers use this for domain-specific claims like organization_id,
	// scopes, roles, plan_tier, billing_status.
	Extra map[string]any
	// SigningKey is the Ed25519 private key used to sign access tokens.
	// The corresponding public key is used by the middleware to verify.
	SigningKey *ed25519.PrivateKey
}

// PasswordGrant implements the OAuth2 password grant per [RFC 6749]
// §4.3. The consumer has already looked up the user and checked any
// business gates (email confirmed, banned, suspended). This function
// verifies the password against the stored hash and issues access +
// refresh tokens.
//
// Parameters:
//   - userID: the user's identifier (becomes the "sub" claim)
//   - email: the user's email (included as the "email" claim)
//   - passwordHash: the stored bcrypt hash
//   - pw: the plaintext password to verify
//
// Returns the signed access token (JWT) and the raw refresh token
// (opaque, to be returned to the client). The refresh token hash is
// stored via the RefreshTokenStore adapter.
func PasswordGrant(ctx context.Context, store RefreshTokenStore, userID, email, passwordHash, pw string, opts GrantOptions) (string, string, error) {
	if err := password.Verify(passwordHash, pw); err != nil {
		return "", "", ErrInvalidCredentials
	}

	return issueTokens(ctx, store, userID, email, opts)
}

// AuthCodeGrant implements the OAuth2 authorization-code grant with
// PKCE per [RFC 6749] §4.1 and [RFC 7636]. The consumer has already
// created the authorization code (via AuthCodeStore.Create) and sent
// it to the client. This function exchanges the code for access +
// refresh tokens.
//
// Parameters:
//   - codeStore: the authorization code store (for code lookup + consumption)
//   - refreshStore: the refresh token store (for new refresh token storage)
//   - code: the raw authorization code from the client
//   - verifier: the PKCE code verifier from the client
//   - redirectURI: the redirect URI from the token request (must match
//     the one bound to the code)
//
// Returns the signed access token (JWT) and the raw refresh token
// (opaque). The authorization code is marked consumed (single-use).
func AuthCodeGrant(ctx context.Context, codeStore AuthCodeStore, refreshStore RefreshTokenStore, code, verifier, redirectURI string, opts GrantOptions) (string, string, error) {
	codeHash := token.HashForStorage(code)

	ac, err := codeStore.GetByHash(ctx, codeHash)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrInvalidGrant, err)
	}

	if ac.ConsumedAt != nil {
		return "", "", ErrInvalidGrant
	}

	if time.Now().After(ac.ExpiresAt) {
		return "", "", ErrExpiredToken
	}

	if ac.CodeChallenge != "" {
		if err := VerifyPKCE(verifier, ac.CodeChallenge, ac.CodeChallengeMethod); err != nil {
			return "", "", err
		}
	}

	if ac.RedirectURI != redirectURI {
		return "", "", ErrInvalidRedirectURI
	}

	if err := codeStore.MarkConsumed(ctx, ac.ID, time.Now()); err != nil {
		return "", "", fmt.Errorf("oauth: failed to mark code consumed: %w", err)
	}

	return issueTokens(ctx, refreshStore, ac.UserID, "", opts)
}

// RefreshTokenGrant implements the OAuth2 refresh-token grant per
// [RFC 6749] §6. Rotates the refresh token: the old token is revoked,
// a new token is issued in the same family. If a revoked token is
// presented again, token reuse is detected and the entire family is
// revoked as a defensive measure.
//
// Parameters:
//   - refreshToken: the raw refresh token from the client
//
// Returns the signed access token (JWT) and the new raw refresh token
// (opaque). The old token is marked revoked; the new token's hash is
// stored via the RefreshTokenStore adapter.
func RefreshTokenGrant(ctx context.Context, store RefreshTokenStore, refreshToken string, opts GrantOptions) (string, string, error) {
	tokenHash := token.HashForStorage(refreshToken)

	rt, err := store.GetByHash(ctx, tokenHash)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrInvalidGrant, err)
	}

	if time.Now().After(rt.ExpiresAt) {
		return "", "", ErrExpiredToken
	}

	if rt.RevokedAt != nil {
		// Token reuse detected — revoke the entire family.
		if err := store.RevokeFamily(ctx, rt.FamilyID); err != nil {
			return "", "", fmt.Errorf("oauth: failed to revoke family after reuse: %w", err)
		}
		return "", "", ErrTokenReuseDetected
	}

	// Mark the old token as revoked (rotation).
	if err := store.MarkRevoked(ctx, rt.ID, time.Now()); err != nil {
		return "", "", fmt.Errorf("oauth: failed to mark token revoked: %w", err)
	}

	// Issue a new refresh token in the same family.
	return issueTokensInFamily(ctx, store, rt.UserID, rt.FamilyID, "", opts)
}

// newID generates a random hex-encoded identifier for tokens and families.
func newID() string {
	b, _ := rand.Bytes(16)
	return hex.EncodeToString(b)
}

// issueTokens issues a new access token (JWT) and refresh token. For
// password and auth-code grants, a new token family is started. For
// refresh grants, use issueTokensInFamily to keep the same family.
func issueTokens(ctx context.Context, store RefreshTokenStore, userID, email string, opts GrantOptions) (string, string, error) {
	familyID := newID()
	return issueTokensInFamily(ctx, store, userID, familyID, email, opts)
}

// issueTokensInFamily issues a new access token (JWT) and refresh token
// in the given family. Used by all three grant flows.
func issueTokensInFamily(ctx context.Context, store RefreshTokenStore, userID, familyID, email string, opts GrantOptions) (string, string, error) {
	now := time.Now()

	// Build access token claims.
	extra := make(map[string]any, len(opts.Extra))
	for k, v := range opts.Extra {
		extra[k] = v
	}
	if email != "" {
		extra["email"] = email
	}

	accessClaims := claims.Claims{
		Issuer:    opts.Issuer,
		Subject:   userID,
		Audience:  []string{opts.Audience},
		ExpiresAt: now.Add(opts.AccessTokenTTL).Unix(),
		IssuedAt:  now.Unix(),
		ID:        newID(),
		Extra:     extra,
	}

	accessToken, err := claims.Sign(accessClaims, opts.SigningKey, claims.Options{
		Algorithm: AlgorithmEdDSA,
	})
	if err != nil {
		return "", "", fmt.Errorf("oauth: failed to sign access token: %w", err)
	}

	// Generate refresh token (opaque, hex-encoded CSPRNG).
	rawRefresh, err := token.Generate(token.DefaultBytes)
	if err != nil {
		return "", "", fmt.Errorf("oauth: failed to generate refresh token: %w", err)
	}

	refreshHash := token.HashForStorage(rawRefresh)

	rt := &RefreshToken{
		ID:        newID(),
		UserID:    userID,
		FamilyID:  familyID,
		TokenHash: refreshHash,
		ExpiresAt: now.Add(opts.RefreshTokenTTL),
	}

	if err := store.Create(ctx, rt); err != nil {
		return "", "", fmt.Errorf("oauth: failed to store refresh token: %w", err)
	}

	return accessToken, rawRefresh, nil
}
