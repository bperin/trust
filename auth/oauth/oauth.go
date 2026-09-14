package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/bperin/trust/auth/claims"
	"github.com/bperin/trust/auth/password"
	"github.com/bperin/trust/auth/token"
	"github.com/bperin/trust/signature"
)

// GrantOptions configures token issuance for all grant flows.
type GrantOptions struct {
	// Issuer is the "iss" claim — identifies the token issuer.
	Issuer string
	// Audience is the "aud" claim — identifies the intended recipient.
	Audience string
	// AccessTokenTTL is the lifetime of the access token.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is the lifetime of the refresh token.
	RefreshTokenTTL time.Duration
	// Extra contains custom claims to include in the access token.
	Extra map[string]any
	// SigningKey is the private key used to sign access tokens. The
	// algorithm is derived from the key type.
	SigningKey crypto.PrivateKey
}

// PasswordGrant implements the OAuth2 password grant ([RFC 6749] §4.3).
// It verifies pw against passwordHash and returns a signed access token
// and a raw refresh token whose hash is stored via store.
func PasswordGrant(ctx context.Context, store RefreshTokenStore, userID, email, passwordHash, pw string, opts GrantOptions) (string, string, error) {
	if err := password.Verify(passwordHash, pw); err != nil {
		return "", "", ErrInvalidCredentials
	}

	return issueTokens(ctx, store, userID, email, opts)
}

// AuthCodeGrant implements the OAuth2 authorization-code grant with
// PKCE ([RFC 6749] §4.1, [RFC 7636]). It validates the code's client
// binding, PKCE verifier, and redirect URI, consumes the single-use
// code atomically, and returns a signed access token and raw refresh
// token.
func AuthCodeGrant(ctx context.Context, codeStore AuthCodeStore, refreshStore RefreshTokenStore, code, verifier, redirectURI, clientID string, opts GrantOptions) (string, string, error) {
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

	// [RFC 6749] §4.1.3 — an authorization code is bound to the client it
	// was issued to; redemption by any other client is rejected. Compared
	// in constant time.
	if subtle.ConstantTimeCompare([]byte(ac.ClientID), []byte(clientID)) != 1 {
		return "", "", ErrInvalidClient
	}

	if ac.CodeChallenge != "" {
		if err := VerifyPKCE(verifier, ac.CodeChallenge, ac.CodeChallengeMethod); err != nil {
			return "", "", err
		}
	}

	if ac.RedirectURI != redirectURI {
		return "", "", ErrInvalidRedirectURI
	}

	// Atomic consume closes the race where two concurrent exchanges both
	// pass the checks above and redeem the same single-use code.
	if err := codeStore.Consume(ctx, ac.ID, time.Now()); err != nil {
		if errors.Is(err, ErrCodeConsumed) {
			return "", "", fmt.Errorf("%w: %w", ErrInvalidGrant, ErrCodeConsumed)
		}
		return "", "", fmt.Errorf("oauth: failed to consume authorization code: %w", err)
	}

	return issueTokens(ctx, refreshStore, ac.UserID, "", opts)
}

// RefreshTokenGrant implements the OAuth2 refresh-token grant
// ([RFC 6749] §6). It rotates the token atomically: the old token is
// revoked and a new one is issued in the same family. Presenting a
// revoked or already-rotated token is treated as reuse and revokes the
// entire family.
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

	// Atomic rotation: claim the token by revoking it. If a concurrent
	// request already consumed it, the store reports ErrTokenRevoked —
	// that is refresh-token reuse.
	if err := store.Revoke(ctx, rt.ID, time.Now()); err != nil {
		if errors.Is(err, ErrTokenRevoked) {
			if rerr := store.RevokeFamily(ctx, rt.FamilyID); rerr != nil {
				return "", "", fmt.Errorf("oauth: failed to revoke family after reuse: %w", rerr)
			}
			return "", "", ErrTokenReuseDetected
		}
		return "", "", fmt.Errorf("oauth: failed to revoke token during rotation: %w", err)
	}

	// Issue a new refresh token in the same family.
	return issueTokensInFamily(ctx, store, rt.UserID, rt.FamilyID, "", opts)
}

// randMu guards randReader, which tests may substitute with a failing
// reader. Substitutions must hold randMu, restore the original via
// t.Cleanup, and must not run in parallel.
var (
	randMu     sync.RWMutex
	randReader io.Reader = rand.Reader
)

// newID returns a random hex-encoded identifier.
func newID() (string, error) {
	b := make([]byte, 16)
	randMu.RLock()
	_, err := io.ReadFull(randReader, b)
	randMu.RUnlock()
	if err != nil {
		return "", fmt.Errorf("oauth: failed to generate random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// issueTokens issues an access token and refresh token in a new family.
func issueTokens(ctx context.Context, store RefreshTokenStore, userID, email string, opts GrantOptions) (string, string, error) {
	familyID, err := newID()
	if err != nil {
		return "", "", err
	}
	return issueTokensInFamily(ctx, store, userID, familyID, email, opts)
}

// issueTokensInFamily issues an access token and refresh token in the
// given family.
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

	tokenID, err := newID()
	if err != nil {
		return "", "", err
	}

	accessClaims := claims.Claims{
		Issuer:    opts.Issuer,
		Subject:   userID,
		Audience:  []string{opts.Audience},
		ExpiresAt: now.Add(opts.AccessTokenTTL).Unix(),
		IssuedAt:  now.Unix(),
		ID:        tokenID,
		Extra:     extra,
	}

	// Derive the JOSE algorithm from the signing key type.
	alg, err := signature.AlgorithmForPrivateKey(opts.SigningKey)
	if err != nil {
		return "", "", fmt.Errorf("oauth: failed to derive signing algorithm: %w", err)
	}

	accessToken, err := claims.Sign(accessClaims, opts.SigningKey, claims.Options{
		Algorithm: alg.JOSE(),
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

	refreshID, err := newID()
	if err != nil {
		return "", "", err
	}

	rt := &RefreshToken{
		ID:        refreshID,
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
