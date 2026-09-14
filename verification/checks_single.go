package verification

import (
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/identity/did"
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

// checkKeyBinding binds the leaf signing key to the issuer and the root proof key to the root subject; no resolver → pass.
func checkKeyBinding(ctx *checkContext) error {
	if ctx.in.IdentityResolver == nil {
		return nil
	}
	if err := bindKeyMatches(ctx, ctx.in.Attestation.Issuer, ctx.in.Attestation.SigningKeyID, ctx.in.SigningKey); err != nil {
		return err
	}
	root := ctx.in.Chain[len(ctx.in.Chain)-1]
	return bindKeyMatches(ctx, root.Authority.Subject, root.Authority.Proof.KeyID, root.PublicKey)
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

// marshalPublicKey renders a public key as comparable bytes.
func marshalPublicKey(k crypto.PublicKey) ([]byte, bool) {
	switch key := k.(type) {
	case *ed25519.PublicKey:
		b := key.Bytes()
		return b[:], true
	case *secp256k1.PublicKey:
		return key.Bytes(), true
	}
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, false
	}
	return der, true
}
