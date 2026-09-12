package oauth

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bperin/auth/claims"
	"github.com/bperin/auth/password"
	"github.com/bperin/auth/token"
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
	return rt, nil
}

func (f *fakeRefreshStore) MarkRevoked(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rt := range f.tokens {
		if rt.ID == id {
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
	return ac, nil
}

func (f *fakeCodeStore) MarkConsumed(_ context.Context, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ac := range f.codes {
		if ac.ID == id {
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
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       challenge,
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	if err := codeStore.Create(ctx, ac); err != nil {
		t.Fatalf("failed to create auth code: %v", err)
	}

	access, refresh, err := AuthCodeGrant(ctx, codeStore, refreshStore, rawCode, verifier, "https://example.com/callback", opts)
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

	_, _, err := AuthCodeGrant(ctx, codeStore, refreshStore, "nonexistent", "verifier", "https://example.com/callback", opts)
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
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(-1 * time.Minute), // expired
	}
	_ = codeStore.Create(ctx, ac)

	_, _, err := AuthCodeGrant(ctx, codeStore, refreshStore, rawCode, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "https://example.com/callback", opts)
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
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		ConsumedAt:          &consumed,
	}
	_ = codeStore.Create(ctx, ac)

	_, _, err := AuthCodeGrant(ctx, codeStore, refreshStore, rawCode, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "https://example.com/callback", opts)
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
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	_ = codeStore.Create(ctx, ac)

	_, _, err := AuthCodeGrant(ctx, codeStore, refreshStore, rawCode, "wrong-verifier", "https://example.com/callback", opts)
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
		CodeHash:            codeHash,
		RedirectURI:         "https://example.com/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: MethodS256,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	_ = codeStore.Create(ctx, ac)

	_, _, err := AuthCodeGrant(ctx, codeStore, refreshStore, rawCode, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "https://wrong.com/callback", opts)
	if !errors.Is(err, ErrInvalidRedirectURI) {
		t.Fatalf("AuthCodeGrant err = %v, want ErrInvalidRedirectURI", err)
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

	// Two goroutines refresh the same token concurrently.
	var wg sync.WaitGroup
	var err1, err2 error
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _, err1 = RefreshTokenGrant(ctx, store, initialRefresh, opts)
	}()
	go func() {
		defer wg.Done()
		_, _, err2 = RefreshTokenGrant(ctx, store, initialRefresh, opts)
	}()
	wg.Wait()

	// One should succeed, the other should detect reuse.
	successCount := 0
	reuseCount := 0
	if err1 == nil {
		successCount++
	} else if errors.Is(err1, ErrTokenReuseDetected) {
		reuseCount++
	}
	if err2 == nil {
		successCount++
	} else if errors.Is(err2, ErrTokenReuseDetected) {
		reuseCount++
	}

	if successCount != 1 {
		t.Fatalf("expected 1 success, got %d (err1=%v, err2=%v)", successCount, err1, err2)
	}
	if reuseCount != 1 {
		t.Fatalf("expected 1 reuse detection, got %d (err1=%v, err2=%v)", reuseCount, err1, err2)
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
