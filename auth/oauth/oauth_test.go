package oauth

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bperin/trust/auth/claims"
	"github.com/bperin/trust/auth/password"
	"github.com/bperin/trust/auth/token"
	trustecdsa "github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/crypto/x25519"
	"github.com/bperin/trust/signature"
)

// --- Fake adapters for testing ---

type fakeRefreshStore struct {
	mu     sync.Mutex
	tokens map[string]*RefreshToken // keyed by TokenHash
}

func newFakeRefreshStore() *fakeRefreshStore {
	return &fakeRefreshStore{tokens: make(map[string]*RefreshToken)}
}

func (f *fakeRefreshStore) Create(_ context.Context, rt *RefreshToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[rt.TokenHash] = rt
	return nil
}

func (f *fakeRefreshStore) GetByHash(_ context.Context, hash string) (*RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rt, ok := f.tokens[hash]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *rt
	return &cp, nil
}

// Revoke atomically marks the token revoked iff it is not already
// revoked — the check-and-set happens under the store mutex, matching
// the atomic semantics RefreshTokenStore requires.
func (f *fakeRefreshStore) Revoke(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rt := range f.tokens {
		if rt.ID == id {
			if rt.RevokedAt != nil {
				return ErrTokenRevoked
			}
			rt.RevokedAt = &at
			return nil
		}
	}
	return errors.New("not found")
}

func (f *fakeRefreshStore) RevokeFamily(_ context.Context, familyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for _, rt := range f.tokens {
		if rt.FamilyID == familyID {
			rt.RevokedAt = &now
		}
	}
	return nil
}

type fakeCodeStore struct {
	mu    sync.Mutex
	codes map[string]*AuthCode // keyed by CodeHash
}

func newFakeCodeStore() *fakeCodeStore {
	return &fakeCodeStore{codes: make(map[string]*AuthCode)}
}

func (f *fakeCodeStore) Create(_ context.Context, ac *AuthCode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes[ac.CodeHash] = ac
	return nil
}

func (f *fakeCodeStore) GetByHash(_ context.Context, hash string) (*AuthCode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ac, ok := f.codes[hash]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *ac
	return &cp, nil
}

// Consume atomically marks the code consumed iff it is not already
// consumed — the check-and-set happens under the store mutex, matching
// the atomic semantics AuthCodeStore requires.
func (f *fakeCodeStore) Consume(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ac := range f.codes {
		if ac.ID == id {
			if ac.ConsumedAt != nil {
				return ErrCodeConsumed
			}
			ac.ConsumedAt = &at
			return nil
		}
	}
	return errors.New("not found")
}

// --- Test helpers ---

func testSigningKey(t *testing.T) crypto.PrivateKey {
	t.Helper()
	priv, _, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	return priv
}

// publicFromPrivate extracts the public key from a crypto.PrivateKey for
// any supported signing key type.
func publicFromPrivate(t *testing.T, priv crypto.PrivateKey) crypto.PublicKey {
	t.Helper()
	switch k := priv.(type) {
	case *ed25519.PrivateKey:
		return k.Public()
	case *secp256k1.PrivateKey:
		return k.Public()
	case *trustecdsa.PrivateKey:
		return k.Public()
	case *rsa.PSSPrivateKey:
		return k.Public()
	case *rsa.PKCS1PrivateKey:
		return k.Public()
	default:
		t.Fatalf("publicFromPrivate: unsupported key type %T", priv)
		return nil
	}
}

func testOpts(t *testing.T) GrantOptions {
	t.Helper()
	return GrantOptions{
		Issuer:          "test-issuer",
		Audience:        "test-audience",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Extra:           map[string]any{"organization_id": "org-123", "roles": []string{"admin"}},
		SigningKey:      testSigningKey(t),
	}
}

// --- PasswordGrant tests ---

func TestPasswordGrant_Success(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newFakeRefreshStore()
	opts := testOpts(t)

	hash, err := password.Hash("correct-password")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	access, refresh, err := PasswordGrant(ctx, store, "user-1", "user@example.com", hash, "correct-password", opts)
	if err != nil {
		t.Fatalf("PasswordGrant failed: %v", err)
	}
	if access == "" {
		t.Fatal("access token is empty")
	}
	if refresh == "" {
		t.Fatal("refresh token is empty")
	}

	// Verify the access token is a valid JWT signed with the derived algorithm.
	pub := publicFromPrivate(t, opts.SigningKey)
	verified, err := claims.Verify(access, pub, claims.Options{
		ExpectedIssuer:   opts.Issuer,
		ExpectedAudience: []string{opts.Audience},
	})
	if err != nil {
		t.Fatalf("access token verification failed: %v", err)
	}
	if verified.Subject != "user-1" {
		t.Fatalf("access token sub = %s, want user-1", verified.Subject)
	}
	if verified.Extra["email"] != "user@example.com" {
		t.Fatalf("access token email = %v, want user@example.com", verified.Extra["email"])
	}
	if verified.Extra["organization_id"] != "org-123" {
		t.Fatalf("access token organization_id = %v, want org-123", verified.Extra["organization_id"])
	}

	// Verify the refresh token was stored by hash.
	refreshHash := token.HashForStorage(refresh)
	stored, err := store.GetByHash(ctx, refreshHash)
	if err != nil {
		t.Fatalf("refresh token not found in store: %v", err)
	}
	if stored.UserID != "user-1" {
		t.Fatalf("stored refresh token UserID = %s, want user-1", stored.UserID)
	}
	if stored.RevokedAt != nil {
		t.Fatal("newly issued refresh token should not be revoked")
	}
}

func TestPasswordGrant_WrongPassword(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newFakeRefreshStore()
	opts := testOpts(t)

	hash, err := password.Hash("correct-password")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	_, _, err = PasswordGrant(ctx, store, "user-1", "user@example.com", hash, "wrong-password", opts)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("PasswordGrant err = %v, want ErrInvalidCredentials", err)
	}
}

func TestPasswordGrant_EmptyPasswordHash(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newFakeRefreshStore()
	opts := testOpts(t)

	_, _, err := PasswordGrant(ctx, store, "user-1", "user@example.com", "", "some-password", opts)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("PasswordGrant err = %v, want ErrInvalidCredentials", err)
	}
}

// --- AuthCodeGrant tests ---

func TestAuthCodeGrant_Success(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codeStore := newFakeCodeStore()
	refreshStore := newFakeRefreshStore()
	opts := testOpts(t)

	// Create an auth code with PKCE S256.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	rawCode := "test-auth-code-123"
	codeHash := token.HashForStorage(rawCode)

	ac := &AuthCode{
		ID:                  "code-1",
		UserID:              "user-1",
		ClientID:            "client-1",
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       challenge,
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	if err := codeStore.Create(ctx, ac); err != nil {
		t.Fatalf("failed to create auth code: %v", err)
	}

	access, refresh, err := AuthCodeGrant(ctx, codeStore, refreshStore, rawCode, verifier, "https://example.com/callback", "client-1", opts)
	if err != nil {
		t.Fatalf("AuthCodeGrant failed: %v", err)
	}
	if access == "" {
		t.Fatal("access token is empty")
	}
	if refresh == "" {
		t.Fatal("refresh token is empty")
	}

	// Verify the code was marked consumed.
	stored, _ := codeStore.GetByHash(ctx, codeHash)
	if stored.ConsumedAt == nil {
		t.Fatal("auth code was not marked consumed")
	}
}

func TestAuthCodeGrant_CodeNotFound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codeStore := newFakeCodeStore()
	refreshStore := newFakeRefreshStore()
	opts := testOpts(t)

	_, _, err := AuthCodeGrant(ctx, codeStore, refreshStore, "nonexistent", "verifier", "https://example.com/callback", "client-1", opts)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("AuthCodeGrant err = %v, want ErrInvalidGrant", err)
	}
}

func TestAuthCodeGrant_ExpiredCode(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codeStore := newFakeCodeStore()
	refreshStore := newFakeRefreshStore()
	opts := testOpts(t)

	rawCode := "expired-code"
	codeHash := token.HashForStorage(rawCode)
	ac := &AuthCode{
		ID:                  "code-1",
		UserID:              "user-1",
		ClientID:            "client-1",
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(-1 * time.Minute), // expired
	}
	_ = codeStore.Create(ctx, ac)

	_, _, err := AuthCodeGrant(ctx, codeStore, refreshStore, rawCode, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "https://example.com/callback", "client-1", opts)
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("AuthCodeGrant err = %v, want ErrExpiredToken", err)
	}
}

func TestAuthCodeGrant_ConsumedCode(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codeStore := newFakeCodeStore()
	refreshStore := newFakeRefreshStore()
	opts := testOpts(t)

	rawCode := "consumed-code"
	codeHash := token.HashForStorage(rawCode)
	consumed := time.Now().Add(-1 * time.Minute)
	ac := &AuthCode{
		ID:                  "code-1",
		UserID:              "user-1",
		ClientID:            "client-1",
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		ConsumedAt:          &consumed,
	}
	_ = codeStore.Create(ctx, ac)

	_, _, err := AuthCodeGrant(ctx, codeStore, refreshStore, rawCode, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "https://example.com/callback", "client-1", opts)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("AuthCodeGrant err = %v, want ErrInvalidGrant", err)
	}
}

func TestAuthCodeGrant_WrongPKCE(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codeStore := newFakeCodeStore()
	refreshStore := newFakeRefreshStore()
	opts := testOpts(t)

	rawCode := "pkce-code"
	codeHash := token.HashForStorage(rawCode)
	ac := &AuthCode{
		ID:                  "code-1",
		UserID:              "user-1",
		ClientID:            "client-1",
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	_ = codeStore.Create(ctx, ac)

	// Valid grammar but wrong verifier — exercises the S256 compare path.
	wrongVerifier := strings.Repeat("v", 43)
	_, _, err := AuthCodeGrant(ctx, codeStore, refreshStore, rawCode, wrongVerifier, "https://example.com/callback", "client-1", opts)
	if !errors.Is(err, ErrInvalidPKCE) {
		t.Fatalf("AuthCodeGrant err = %v, want ErrInvalidPKCE", err)
	}
}

func TestAuthCodeGrant_WrongRedirectURI(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codeStore := newFakeCodeStore()
	refreshStore := newFakeRefreshStore()
	opts := testOpts(t)

	rawCode := "redirect-code"
	codeHash := token.HashForStorage(rawCode)
	ac := &AuthCode{
		ID:                  "code-1",
		UserID:              "user-1",
		ClientID:            "client-1",
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	_ = codeStore.Create(ctx, ac)

	_, _, err := AuthCodeGrant(ctx, codeStore, refreshStore, rawCode, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "https://wrong.com/callback", "client-1", opts)
	if !errors.Is(err, ErrInvalidRedirectURI) {
		t.Fatalf("AuthCodeGrant err = %v, want ErrInvalidRedirectURI", err)
	}
}

// --- A13: client-bound redemption and atomic consume ---

// TestAuthCodeGrant_DifferentClientRejected verifies [A13] client
// binding per [RFC 6749] §4.1.3: an authorization code can only be
// redeemed by the client it was issued to.
func TestAuthCodeGrant_DifferentClientRejected(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codeStore := newFakeCodeStore()
	refreshStore := newFakeRefreshStore()
	opts := testOpts(t)

	rawCode := "client-bound-code"
	codeHash := token.HashForStorage(rawCode)
	ac := &AuthCode{
		ID:                  "code-1",
		UserID:              "user-1",
		ClientID:            "client-1",
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	_ = codeStore.Create(ctx, ac)

	tests := []struct {
		name     string
		clientID string
		wantErr  error
	}{
		{"different client rejected", "client-2", ErrInvalidClient},
		{"empty client rejected", "", ErrInvalidClient},
		{"issuing client accepted", "client-1", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset the code between subtests — a successful redemption
			// consumes it.
			ac.ConsumedAt = nil

			_, _, err := AuthCodeGrant(ctx, codeStore, refreshStore, rawCode,
				"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "https://example.com/callback", tt.clientID, opts)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("AuthCodeGrant with issuing client: got err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("AuthCodeGrant with client %q: got err = %v, want %v", tt.clientID, err, tt.wantErr)
			}
			// A rejected exchange must not consume the code.
			if ac.ConsumedAt != nil {
				t.Fatalf("AuthCodeGrant with client %q: code consumed despite rejection", tt.clientID)
			}
		})
	}
}

// TestAuthCodeGrant_ConcurrentRedemption verifies [A13] atomic consume:
// when N goroutines race to redeem the same authorization code, exactly
// one succeeds and every loser fails with ErrInvalidGrant. Run under
// `go test -race`.
func TestAuthCodeGrant_ConcurrentRedemption(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	codeStore := newFakeCodeStore()
	refreshStore := newFakeRefreshStore()
	opts := testOpts(t)

	rawCode := "concurrent-code"
	codeHash := token.HashForStorage(rawCode)
	ac := &AuthCode{
		ID:                  "code-1",
		UserID:              "user-1",
		ClientID:            "client-1",
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	_ = codeStore.Create(ctx, ac)

	const racers = 8
	var wg sync.WaitGroup
	errs := make([]error, racers)
	wg.Add(racers)
	for i := range racers {
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = AuthCodeGrant(ctx, codeStore, refreshStore, rawCode,
				"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "https://example.com/callback", "client-1", opts)
		}(i)
	}
	wg.Wait()

	successCount := 0
	for i, err := range errs {
		if err == nil {
			successCount++
			continue
		}
		if !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("racer %d: err = %v, want nil or ErrInvalidGrant", i, err)
		}
	}

	if successCount != 1 {
		t.Fatalf("concurrent redemption: got %d successes, want exactly 1 (errs=%v)", successCount, errs)
	}
}

// --- RefreshTokenGrant tests ---

func TestRefreshTokenGrant_Success(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newFakeRefreshStore()
	opts := testOpts(t)

	// Issue an initial refresh token via password grant.
	hash, _ := password.Hash("correct-password")
	_, initialRefresh, err := PasswordGrant(ctx, store, "user-1", "user@example.com", hash, "correct-password", opts)
	if err != nil {
		t.Fatalf("PasswordGrant failed: %v", err)
	}

	// Now refresh it.
	access, newRefresh, err := RefreshTokenGrant(ctx, store, initialRefresh, opts)
	if err != nil {
		t.Fatalf("RefreshTokenGrant failed: %v", err)
	}
	if access == "" {
		t.Fatal("access token is empty")
	}
	if newRefresh == "" {
		t.Fatal("new refresh token is empty")
	}
	if newRefresh == initialRefresh {
		t.Fatal("new refresh token should differ from old")
	}

	// Old token should be revoked.
	oldHash := token.HashForStorage(initialRefresh)
	oldToken, _ := store.GetByHash(ctx, oldHash)
	if oldToken.RevokedAt == nil {
		t.Fatal("old refresh token should be revoked after rotation")
	}

	// New token should not be revoked.
	newHash := token.HashForStorage(newRefresh)
	newToken, _ := store.GetByHash(ctx, newHash)
	if newToken.RevokedAt != nil {
		t.Fatal("new refresh token should not be revoked")
	}

	// New token should be in the same family.
	if newToken.FamilyID != oldToken.FamilyID {
		t.Fatal("new refresh token should be in the same family as old")
	}
}

func TestRefreshTokenGrant_TokenNotFound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newFakeRefreshStore()
	opts := testOpts(t)

	_, _, err := RefreshTokenGrant(ctx, store, "nonexistent-token", opts)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("RefreshTokenGrant err = %v, want ErrInvalidGrant", err)
	}
}

func TestRefreshTokenGrant_ExpiredToken(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newFakeRefreshStore()
	opts := testOpts(t)

	// Manually insert an expired token.
	rawToken := "expired-refresh"
	tokenHash := token.HashForStorage(rawToken)
	rt := &RefreshToken{
		ID:        "rt-1",
		UserID:    "user-1",
		FamilyID:  "family-1",
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(-1 * time.Minute), // expired
	}
	_ = store.Create(ctx, rt)

	_, _, err := RefreshTokenGrant(ctx, store, rawToken, opts)
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("RefreshTokenGrant err = %v, want ErrExpiredToken", err)
	}
}

func TestRefreshTokenGrant_ReuseDetection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newFakeRefreshStore()
	opts := testOpts(t)

	// Issue an initial refresh token.
	hash, _ := password.Hash("correct-password")
	_, initialRefresh, err := PasswordGrant(ctx, store, "user-1", "user@example.com", hash, "correct-password", opts)
	if err != nil {
		t.Fatalf("PasswordGrant failed: %v", err)
	}

	// Refresh it once (normal rotation).
	_, newRefresh, err := RefreshTokenGrant(ctx, store, initialRefresh, opts)
	if err != nil {
		t.Fatalf("first RefreshTokenGrant failed: %v", err)
	}
	_ = newRefresh

	// Try to use the old (now revoked) token again — reuse detected.
	_, _, err = RefreshTokenGrant(ctx, store, initialRefresh, opts)
	if !errors.Is(err, ErrTokenReuseDetected) {
		t.Fatalf("RefreshTokenGrant err = %v, want ErrTokenReuseDetected", err)
	}

	// The entire family should be revoked.
	oldHash := token.HashForStorage(initialRefresh)
	oldToken, _ := store.GetByHash(ctx, oldHash)
	if oldToken.RevokedAt == nil {
		t.Fatal("old token should be revoked after reuse detection")
	}

	newHash := token.HashForStorage(newRefresh)
	newToken, _ := store.GetByHash(ctx, newHash)
	if newToken.RevokedAt == nil {
		t.Fatal("new token should also be revoked after family revocation")
	}
}

// TestRefreshTokenGrant_Concurrent verifies [A13] atomic rotation: when
// N goroutines race to refresh the same token, exactly one succeeds and
// every loser detects reuse. Run under `go test -race`.
func TestRefreshTokenGrant_Concurrent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newFakeRefreshStore()
	opts := testOpts(t)

	// Issue an initial refresh token.
	hash, _ := password.Hash("correct-password")
	_, initialRefresh, err := PasswordGrant(ctx, store, "user-1", "user@example.com", hash, "correct-password", opts)
	if err != nil {
		t.Fatalf("PasswordGrant failed: %v", err)
	}

	const racers = 8
	var wg sync.WaitGroup
	errs := make([]error, racers)
	wg.Add(racers)
	for i := range racers {
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = RefreshTokenGrant(ctx, store, initialRefresh, opts)
		}(i)
	}
	wg.Wait()

	// Exactly one succeeds; every loser must detect reuse.
	successCount := 0
	reuseCount := 0
	for i, err := range errs {
		switch {
		case err == nil:
			successCount++
		case errors.Is(err, ErrTokenReuseDetected):
			reuseCount++
		default:
			t.Fatalf("racer %d: err = %v, want nil or ErrTokenReuseDetected", i, err)
		}
	}

	if successCount != 1 {
		t.Fatalf("concurrent rotation: got %d successes, want exactly 1 (errs=%v)", successCount, errs)
	}
	if reuseCount != racers-1 {
		t.Fatalf("concurrent rotation: got %d reuse detections, want %d (errs=%v)", reuseCount, racers-1, errs)
	}
}

// --- A13: randomness errors are surfaced, never discarded ---

// errEntropy is the sentinel the failing test readers return.
var errEntropy = errors.New("entropy source failure")

// errReader is an io.Reader whose Read always fails.
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errEntropy
}

// shortReader is an io.Reader that returns fewer bytes than requested.
type shortReader struct{}

func (shortReader) Read(p []byte) (int, error) {
	return copy(p, "ab"), io.EOF
}

// stubRandReader swaps the package-level entropy source for the test and
// restores it on cleanup. Tests using it must not run in parallel —
// parallel tests are parked while sequential tests run, but a parallel
// stub would inject failures into unrelated grants.
func stubRandReader(t *testing.T, r io.Reader) {
	t.Helper()
	randMu.Lock()
	old := randReader
	randReader = r
	randMu.Unlock()
	t.Cleanup(func() {
		randMu.Lock()
		randReader = old
		randMu.Unlock()
	})
}

// TestNewID verifies [A13]: newID produces unique 32-hex-char identifiers
// and surfaces entropy-source failures instead of returning a
// predictable zero-filled identifier.
func TestNewID(t *testing.T) {
	tests := []struct {
		name    string
		reader  io.Reader // nil means keep the real CSPRNG
		wantErr error
	}{
		{"crypto/rand produces identifier", nil, nil},
		{"entropy failure surfaced", errReader{}, errEntropy},
		{"short read surfaced", shortReader{}, io.ErrUnexpectedEOF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.reader != nil {
				stubRandReader(t, tt.reader)
			}

			id, err := newID()
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("newID: got nil error, want %v", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("newID: got err = %v, want errors.Is(_, %v)", err, tt.wantErr)
				}
				if id != "" {
					t.Fatalf("newID: got id = %q on failure, want empty", id)
				}
				return
			}

			if err != nil {
				t.Fatalf("newID: got err = %v, want nil", err)
			}
			if len(id) != 32 {
				t.Fatalf("newID: got id %q (len %d), want 32 hex chars", id, len(id))
			}
			other, err := newID()
			if err != nil {
				t.Fatalf("newID (second call): got err = %v, want nil", err)
			}
			if id == other {
				t.Fatalf("newID: got duplicate ids %q, want unique", id)
			}
		})
	}
}

// TestGrants_RandomnessError verifies [A13]: every grant flow surfaces a
// randomness failure as an error instead of silently issuing tokens with
// a predictable identifier. Not parallel — it stubs the entropy source.
func TestGrants_RandomnessError(t *testing.T) {
	ctx := context.Background()

	hash, err := password.Hash("correct-password")
	if err != nil {
		t.Fatalf("password.Hash: %v", err)
	}

	// Fixtures created while the entropy source is healthy.
	codeStore := newFakeCodeStore()
	rawCode := "rand-fail-code"
	codeHash := token.HashForStorage(rawCode)
	_ = codeStore.Create(ctx, &AuthCode{
		ID:                  "code-1",
		UserID:              "user-1",
		ClientID:            "client-1",
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	})

	refreshStore := newFakeRefreshStore()
	_, liveRefresh, err := PasswordGrant(ctx, refreshStore, "user-1", "user@example.com", hash, "correct-password", testOpts(t))
	if err != nil {
		t.Fatalf("PasswordGrant setup: %v", err)
	}

	tests := []struct {
		name  string
		grant func(GrantOptions) error
	}{
		{
			name: "password grant",
			grant: func(o GrantOptions) error {
				_, _, err := PasswordGrant(ctx, newFakeRefreshStore(), "user-1", "user@example.com", hash, "correct-password", o)
				return err
			},
		},
		{
			name: "auth code grant",
			grant: func(o GrantOptions) error {
				_, _, err := AuthCodeGrant(ctx, codeStore, newFakeRefreshStore(), rawCode,
					"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "https://example.com/callback", "client-1", o)
				return err
			},
		},
		{
			name: "refresh token grant",
			grant: func(o GrantOptions) error {
				_, _, err := RefreshTokenGrant(ctx, refreshStore, liveRefresh, o)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubRandReader(t, errReader{})

			err := tt.grant(testOpts(t))
			if err == nil {
				t.Fatal("grant: got nil error, want entropy failure surfaced")
			}
			if !errors.Is(err, errEntropy) {
				t.Fatalf("grant: got err = %v, want errors.Is(_, %v)", err, errEntropy)
			}
		})
	}
}

// --- Algorithm widening tests ---

// signingKeyPair holds a generated private/public key pair for testing.
type signingKeyPair struct {
	priv crypto.PrivateKey
	pub  crypto.PublicKey
	alg  string // expected JOSE algorithm name
}

// generateSigningKeyPair generates a key pair for the given algorithm family.
func generateSigningKeyPair(t *testing.T, alg string) signingKeyPair {
	t.Helper()
	switch alg {
	case "EdDSA":
		priv, pub, err := ed25519.GenerateKey()
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		return signingKeyPair{priv, pub, "EdDSA"}
	case "ES256K":
		priv, pub, err := secp256k1.GenerateKey()
		if err != nil {
			t.Fatalf("secp256k1.GenerateKey: %v", err)
		}
		return signingKeyPair{priv, pub, "ES256K"}
	case "ES256":
		priv, pub, err := trustecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey P-256: %v", err)
		}
		return signingKeyPair{priv, pub, "ES256"}
	case "PS256":
		priv, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePSSKey: %v", err)
		}
		return signingKeyPair{priv, pub, "PS256"}
	case "RS256":
		priv, pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePKCS1Key: %v", err)
		}
		return signingKeyPair{priv, pub, "RS256"}
	default:
		t.Fatalf("unsupported algorithm: %s", alg)
		return signingKeyPair{}
	}
}

// optsWithKey returns GrantOptions configured with the given signing key.
func optsWithKey(key crypto.PrivateKey) GrantOptions {
	return GrantOptions{
		Issuer:          "test-issuer",
		Audience:        "test-audience",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Extra:           map[string]any{"organization_id": "org-123"},
		SigningKey:      key,
	}
}

// TestPasswordGrant_AllAlgorithms verifies that PasswordGrant works with
// every supported signing algorithm family.
func TestPasswordGrant_AllAlgorithms(t *testing.T) {
	t.Parallel()

	algorithms := []string{"EdDSA", "ES256K", "ES256", "PS256", "RS256"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			ctx := context.Background()
			store := newFakeRefreshStore()
			kp := generateSigningKeyPair(t, alg)
			opts := optsWithKey(kp.priv)

			hash, err := password.Hash("correct-password")
			if err != nil {
				t.Fatalf("password.Hash: %v", err)
			}

			access, refresh, err := PasswordGrant(ctx, store, "user-1", "user@example.com", hash, "correct-password", opts)
			if err != nil {
				t.Fatalf("PasswordGrant: %v", err)
			}
			if access == "" {
				t.Fatal("access token is empty")
			}
			if refresh == "" {
				t.Fatal("refresh token is empty")
			}

			// Verify the token with the corresponding public key.
			verified, err := claims.Verify(access, kp.pub, claims.Options{
				ExpectedIssuer:   opts.Issuer,
				ExpectedAudience: []string{opts.Audience},
			})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if verified.Subject != "user-1" {
				t.Errorf("Subject: got %q, want %q", verified.Subject, "user-1")
			}
		})
	}
}

// TestPasswordGrant_UnsupportedKey verifies that an unrecognized key type
// (x25519 — a key exchange key, not a signing key) returns a typed error.
func TestPasswordGrant_UnsupportedKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newFakeRefreshStore()

	priv, _, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("x25519.GenerateKey: %v", err)
	}

	opts := optsWithKey(priv)
	hash, _ := password.Hash("correct-password")

	_, _, err = PasswordGrant(ctx, store, "user-1", "user@example.com", hash, "correct-password", opts)
	if err == nil {
		t.Fatal("PasswordGrant with x25519: expected error, got nil")
	}
	if !errors.Is(err, signature.ErrUnsupportedAlgorithm) {
		t.Errorf("PasswordGrant with x25519: err = %v, want errors.Is(_, signature.ErrUnsupportedAlgorithm)", err)
	}
}

// TestEd25519BackwardCompat verifies that an Ed25519 key produces a token
// with alg: "EdDSA" that verifies — preserving the pre-widening behavior.
func TestEd25519BackwardCompat(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newFakeRefreshStore()
	opts := testOpts(t)

	hash, err := password.Hash("correct-password")
	if err != nil {
		t.Fatalf("password.Hash: %v", err)
	}

	access, _, err := PasswordGrant(ctx, store, "user-1", "user@example.com", hash, "correct-password", opts)
	if err != nil {
		t.Fatalf("PasswordGrant: %v", err)
	}

	// Extract the alg header to confirm it's EdDSA.
	headerJSON, err := base64.RawURLEncoding.DecodeString(access[:strings.IndexByte(access, '.')])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	gotAlg, _ := header["alg"].(string)
	if gotAlg != "EdDSA" {
		t.Errorf("alg header: got %q, want %q", gotAlg, "EdDSA")
	}

	// Verify the token with the public key (no explicit Algorithm — derived).
	pub := publicFromPrivate(t, opts.SigningKey)
	_, err = claims.Verify(access, pub, claims.Options{
		ExpectedIssuer: opts.Issuer,
		Now:            func() time.Time { return time.Now() },
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
