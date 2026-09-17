package verification

import (
	"crypto"
	stdecdsa "crypto/ecdsa"
	stdrsa "crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/identity/did"
	"github.com/bperin/trust/signature"
)

// checkStructural validates the attestation's structure.
func checkStructural(ctx *checkContext) error {
	if err := attestation.Validate(ctx.in.Attestation); err != nil {
		return fmt.Errorf("verification: structural: %w: %w", ErrStructural, err)
	}
	return nil
}

// checkSignature verifies the attestation signature; ErrWrongKey maps to ErrSignatureKeyMismatch, the rest to ErrSignatureMismatch.
func checkSignature(ctx *checkContext) error {
	err := attestation.VerifySignature(ctx.in.Attestation, ctx.in.SigningKey)
	if err == nil {
		return nil
	}
	if errors.Is(err, attestation.ErrWrongKey) {
		return fmt.Errorf("verification: signature key: %w", ErrSignatureKeyMismatch)
	}
	return fmt.Errorf("verification: signature: %w", ErrSignatureMismatch)
}

// checkAuthorization verifies the attestation is authorized by the leaf authority.
func checkAuthorization(ctx *checkContext) error {
	err := attestation.VerifyAuthorization(ctx.in.Attestation, ctx.in.Chain[0].Authority)
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, attestation.ErrCapabilityNotGranted):
		return fmt.Errorf("verification: authorization: %w", ErrCapabilityNotGranted)
	case errors.Is(err, attestation.ErrAuthorizationScope):
		return fmt.Errorf("verification: authorization: %w", ErrScopeViolation)
	default:
		return fmt.Errorf("verification: authorization: %w: %w", ErrAuthorityInvalid, err)
	}
}

// checkRootAuthority verifies the final hop has no parent.
func checkRootAuthority(ctx *checkContext) error {
	last := ctx.in.Chain[len(ctx.in.Chain)-1].Authority
	if last.Parent != nil {
		return ErrNotRootAuthority
	}
	return nil
}

// checkKeyBinding rejects a superseded or revoked signing-key version, then binds the leaf signing key to the issuer and the root proof key to the root subject; no resolver → pass.
func checkKeyBinding(ctx *checkContext) error {
	if err := checkSigningKeyVersion(ctx); err != nil {
		return err
	}
	if ctx.in.IdentityResolver == nil {
		return nil
	}
	if err := bindKeyMatches(ctx, ctx.in.Attestation.Issuer, ctx.in.Attestation.SigningKeyID, ctx.in.SigningKey); err != nil {
		return err
	}
	root := ctx.in.Chain[len(ctx.in.Chain)-1]
	return bindKeyMatches(ctx, root.Authority.Subject, root.Authority.Proof.KeyID, root.PublicKey)
}

// checkSigningKeyVersion fails the check when the version that signed the attestation is no longer the identity's bound version; no history → pass.
func checkSigningKeyVersion(ctx *checkContext) error {
	history := ctx.in.KeyVersions
	if len(history) == 0 {
		return nil
	}
	used := ctx.in.Attestation.SigningKeyVersion
	bound, ok := keyVersionAt(history, ctx.now)
	if !ok {
		return fmt.Errorf("verification: key binding: %w: no signing key version bound at %s", ErrKeyBinding, ctx.now.Format(time.RFC3339))
	}
	switch {
	case used < bound.Version:
		return fmt.Errorf("verification: key binding: %w: version %d superseded by version %d at %s",
			ErrKeyVersionSuperseded, used, bound.Version, bound.BoundAt.Format(time.RFC3339))
	case used > bound.Version:
		return fmt.Errorf("verification: key binding: %w: version %d is not bound to the identity", ErrKeyBinding, used)
	case !bound.RevokedAt.IsZero() && !ctx.now.Before(bound.RevokedAt):
		return fmt.Errorf("verification: key binding: %w: version %d revoked at %s", ErrRevoked, used, bound.RevokedAt.Format(time.RFC3339))
	}
	return nil
}

// keyVersionAt returns the highest-version entry bound at or before now.
func keyVersionAt(history []KeyVersion, now time.Time) (KeyVersion, bool) {
	var (
		bound KeyVersion
		found bool
	)
	for _, v := range history {
		if now.Before(v.BoundAt) {
			continue
		}
		if !found || v.BoundAt.After(bound.BoundAt) || (v.BoundAt.Equal(bound.BoundAt) && v.Version > bound.Version) {
			bound, found = v, true
		}
	}
	return bound, found
}

// bindKeyMatches resolves subject's DID document and compares the key bound to keyID against want.
func bindKeyMatches(ctx *checkContext, subject, keyID string, want crypto.PublicKey) error {
	d, err := did.Parse(subject)
	if err != nil {
		return fmt.Errorf("verification: key binding: %w: %v", ErrKeyBinding, err)
	}
	doc, err := ctx.in.IdentityResolver.Resolve(d)
	if err != nil {
		return fmt.Errorf("verification: key binding: %w: %v", ErrKeyBinding, err)
	}
	bound, err := ctx.e.binder.Bind(keyID, doc)
	if err != nil {
		return fmt.Errorf("verification: key binding: %w: %v", ErrKeyBinding, err)
	}
	if !samePublicKey(bound, want) {
		return fmt.Errorf("verification: key binding: %w: key for %q does not match supplied key", ErrKeyBinding, keyID)
	}
	return sameKeyAlgorithm(bound, want, keyID)
}

// sameKeyAlgorithm reports the bound and supplied keys resolving to different signature algorithms.
func sameKeyAlgorithm(bound, want crypto.PublicKey, keyID string) error {
	ba, err := signature.AlgorithmForPublicKey(bound)
	if err != nil {
		return fmt.Errorf("verification: key binding: %w: bound key for %q: %v", ErrKeyBinding, keyID, err)
	}
	wa, err := signature.AlgorithmForPublicKey(want)
	if err != nil {
		return fmt.Errorf("verification: key binding: %w: supplied key for %q: %v", ErrKeyBinding, keyID, err)
	}
	if ba != wa {
		return fmt.Errorf("verification: key binding: %w: key for %q is a %s key, supplied key is %s",
			ErrKeyBinding, keyID, algorithmName(ba), algorithmName(wa))
	}
	return nil
}

// samePublicKey reports whether two public keys are the same key.
func samePublicKey(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ab, aok := marshalPublicKey(a)
	bb, bok := marshalPublicKey(b)
	if aok && bok {
		return subtle.ConstantTimeCompare(ab, bb) == 1
	}
	return false
}

// marshalPublicKey renders a public key as comparable bytes, mapping each
// trust wrapper onto the standard key it holds.
func marshalPublicKey(k crypto.PublicKey) ([]byte, bool) {
	switch key := k.(type) {
	case *ed25519.PublicKey:
		b := key.Bytes()
		return b[:], true
	case *secp256k1.PublicKey:
		return key.Bytes(), true
	case *ecdsa.PublicKey:
		k = &stdecdsa.PublicKey{Curve: key.Curve(), X: key.X(), Y: key.Y()}
	case *rsa.PSSPublicKey:
		k = &stdrsa.PublicKey{N: key.N(), E: key.E()}
	case *rsa.PKCS1PublicKey:
		k = &stdrsa.PublicKey{N: key.N(), E: key.E()}
	}
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, false
	}
	return der, true
}
