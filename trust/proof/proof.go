package proof

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/bperin/trust/trust/attestation"
	"github.com/bperin/trust/trust/authority"
	"github.com/bperin/trust/trust/signature"
)

// Sentinel errors returned by BuildProof and VerifyProof. Check them
// with errors.Is. The chain and attestation sentinels are re-exported
// from their underlying packages so errors.Is works across layer
// boundaries without import cycles.
var (
	// ErrScopeViolation is returned when a delegation link declares a
	// scope dimension outside its parent's effective scope. Re-exported
	// from authority so a proof-level errors.Is check matches the
	// underlying authority error.
	ErrScopeViolation = authority.ErrScopeViolation

	// ErrBrokenDelegationChain is returned when a delegation link's
	// parent signature is missing, malformed, or does not verify, or
	// when the chain's ParentAuthorityRef linkage is broken. This wraps
	// authority.ErrBrokenSignature and authority.ErrChainBroken.
	ErrBrokenDelegationChain = errors.New("proof: broken delegation chain")

	// ErrKeyVersionNonMonotonic is returned when a link's KeyVersion is
	// lower than the preceding link's — versions must be non-decreasing
	// within a presented chain. Re-exported from authority.
	ErrKeyVersionNonMonotonic = authority.ErrKeyVersionNonMonotonic

	// ErrTamperedAttestation is returned when the attestation's stored
	// Signature does not verify against the recomputed canonical hash
	// under the leaf key. Re-exported from attestation.
	ErrTamperedAttestation = attestation.ErrTamperedAttestation

	// ErrWrongRootKey is returned when the supplied root public key does
	// not verify the first delegation link — the verifier supplied the
	// wrong root anchor.
	ErrWrongRootKey = errors.New("proof: wrong root key")

	// ErrCapabilityNotCovered is returned when the attestation's claim
	// capability is not in the intersected scope's effective Actions
	// set. Re-exported from authority so both link-level and
	// claim-level capability violations match the same sentinel.
	ErrCapabilityNotCovered = authority.ErrCapabilityNotCovered
)

// Proof is a self-contained attestation proof carrying everything a
// verifier needs for offline verification: the signed attestation, the
// full delegation chain from the root anchor to the leaf signing key,
// the key version the attestation was signed under, the advisory
// intersected scope, and the canonical hash of the root organization
// identity for context.
//
// The verifier supplies only the root public key; every other input
// comes from the proof. IntersectedScope is advisory — VerifyProof
// re-intersects the chain at verification time via
// authority.VerifyChain and never trusts the cached value.
type Proof struct {
	// Attestation is the signed attestation produced by the leaf
	// signing key. Its Signature is verified against the leaf public
	// key derived from the delegation chain.
	Attestation attestation.Attestation

	// DelegationChain is the full ordered chain from the root-issued
	// link (index 0) to the leaf signing key (last index). VerifyProof
	// verifies every parent-child signature and re-intersects scopes.
	DelegationChain authority.DelegationChain

	// SigningKeyVersion is the key version the attestation was signed
	// under. VerifyProof asserts this matches the leaf link's
	// KeyVersion.
	SigningKeyVersion uint64

	// IntersectedScope is the cached scope intersection computed at
	// build time. It is advisory only — VerifyProof re-computes the
	// intersection from the chain and root key at verification time
	// and never trusts this value. It is carried so callers that
	// transport the proof can inspect the intended scope without
	// re-verifying.
	IntersectedScope authority.Scope

	// RootOrganizationHash is the canonical hash of the root
	// organization identity that owns the root key. It is context
	// metadata — VerifyProof does not gate on it. The verifier
	// supplies the root public key; this hash lets the proof carry
	// which organization the root anchor belongs to.
	RootOrganizationHash [32]byte
}

// BuildProof assembles a Proof from a signed attestation and a
// delegation chain. It validates the chain structure via
// authority.BuildChain and verifies the attestation signature against
// the leaf public key derived from the chain's last link before
// returning. The intersected scope is left as the zero value — it is
// advisory and re-computed at verification time.
//
// The attestation must already be signed (via
// attestation.SignAttestation) with the leaf key that corresponds to
// the chain's last link public key. BuildProof verifies this binding
// by calling attestation.VerifyAttestation with the leaf public key.
//
// The chain must be a complete, signed delegation chain built via
// authority.BuildChain. BuildProof re-validates its structure
// (ParentAuthorityRef linkage and signature presence) but does not
// verify signatures — that requires the root public key, which
// BuildProof does not take. Signature verification is VerifyProof's
// job.
func BuildProof(att attestation.Attestation, chain authority.DelegationChain) (Proof, error) {
	if len(chain) == 0 {
		return Proof{}, fmt.Errorf("%w: empty delegation chain", ErrBrokenDelegationChain)
	}

	// Validate chain structure: ParentAuthorityRef linkage and
	// signature presence. BuildChain returns a copy; we discard it
	// and carry the original chain so the proof holds the exact
	// links the caller built.
	if _, err := authority.BuildChain(chain...); err != nil {
		return Proof{}, fmt.Errorf("proof build: %w", err)
	}

	// Derive the leaf public key from the last link.
	leafPub := chain[len(chain)-1].PublicKey
	if leafPub == nil {
		return Proof{}, fmt.Errorf("proof build: %w: leaf link has no public key", ErrBrokenDelegationChain)
	}

	// Verify the attestation signature against the leaf key. This
	// confirms the attestation was signed by the key the chain
	// delegates to.
	if err := attestation.VerifyAttestation(&att, leafPub); err != nil {
		return Proof{}, fmt.Errorf("proof build: %w", err)
	}

	return Proof{
		Attestation:       att,
		DelegationChain:   chain,
		SigningKeyVersion: chain[len(chain)-1].KeyVersion,
		// IntersectedScope is advisory; left as zero. VerifyProof
		// re-intersects at verification time.
	}, nil
}

// VerifyProof is a pure function that verifies a Proof against the
// supplied root public key. It performs no I/O, no network calls, no
// database lookups, and reads no global state. Everything except the
// root public key comes from the proof.
//
// Verification proceeds in order:
//
//  1. The root public key is checked against the first delegation
//     link's signature (ErrWrongRootKey). This distinguishes a wrong
//     root anchor from a broken chain link.
//  2. authority.VerifyChain verifies every parent-child signature,
//     re-intersects scopes top-to-bottom, and checks key version
//     monotonicity. Signature or linkage failures are wrapped as
//     ErrBrokenDelegationChain; scope violations surface as
//     ErrScopeViolation; non-monotonic versions surface as
//     ErrKeyVersionNonMonotonic.
//  3. The leaf public key is derived from the chain's last link and
//     attestation.VerifyAttestation verifies the attestation signature
//     (ErrTamperedAttestation).
//  4. The proof's SigningKeyVersion is asserted to match the leaf
//     link's KeyVersion.
//  5. The attestation's claim capability (claim.Schema) is asserted to
//     be covered by the intersected scope's Actions set
//     (ErrCapabilityNotCovered). An empty Actions set means
//     unrestricted.
//
// The returned Scope is the re-intersected effective scope — the
// tightest bound implied by the full chain. It is by construction a
// subset of every ancestor's declared scope.
//
// Project algorithms and governing standards:
//
//   - ed25519      [RFC 8037]; [FIPS 186-5]
//   - secp256k1    [SEC 2 v2]; [RFC 6979]; [EIP-2]
//   - ecdsa-p256   [FIPS 186-4] (P-256)
//   - ecdsa-p384   [FIPS 186-4] (P-384)
//   - rsa-pss      [RFC 8017] (PKCS#1 v2.2, PSS)
//   - rsa-pkcs1v15 [RFC 8017] §8.2
func VerifyProof(p Proof, rootPub crypto.PublicKey) (authority.Scope, error) {
	if rootPub == nil {
		return authority.Scope{}, fmt.Errorf("%w: nil root key", ErrWrongRootKey)
	}
	if len(p.DelegationChain) == 0 {
		return authority.Scope{}, fmt.Errorf("%w: empty delegation chain", ErrBrokenDelegationChain)
	}

	// Step 1: pre-check the root key against the first link. This
	// distinguishes a wrong root anchor from a broken chain link.
	// The first link's ParentSignature is the root key's signature
	// over the canonical hash of the unsigned link payload. We
	// compute the signing hash by zeroing ParentSignature and
	// calling authority.CanonicalHash — with omitempty on the
	// parentSignature JSON field, a nil signature is omitted,
	// producing the same bytes as the authority-internal
	// signingHash.
	first := p.DelegationChain[0]
	if err := verifyRootLink(first, rootPub); err != nil {
		return authority.Scope{}, err
	}

	// Step 2: verify the full chain — signatures, scope
	// intersection, key version monotonicity.
	scope, err := authority.VerifyChain(p.DelegationChain, rootPub)
	if err != nil {
		switch {
		case errors.Is(err, authority.ErrBrokenSignature) || errors.Is(err, authority.ErrChainBroken):
			// The root key already verified the first link, so a
			// signature failure here is a broken chain link, not a
			// wrong root key.
			return authority.Scope{}, fmt.Errorf("%w: %w", ErrBrokenDelegationChain, err)
		case errors.Is(err, authority.ErrScopeViolation):
			// Re-exported; errors.Is already matches proof.ErrScopeViolation.
			return authority.Scope{}, err
		case errors.Is(err, authority.ErrKeyVersionNonMonotonic):
			// Re-exported; errors.Is already matches proof.ErrKeyVersionNonMonotonic.
			return authority.Scope{}, err
		case errors.Is(err, authority.ErrCapabilityNotCovered):
			// Re-exported; errors.Is already matches proof.ErrCapabilityNotCovered.
			return authority.Scope{}, err
		default:
			return authority.Scope{}, fmt.Errorf("proof verify: %w", err)
		}
	}

	// Step 3: derive the leaf public key and verify the attestation.
	leafPub := p.DelegationChain[len(p.DelegationChain)-1].PublicKey
	if leafPub == nil {
		return authority.Scope{}, fmt.Errorf("%w: leaf link has no public key", ErrBrokenDelegationChain)
	}
	if err := attestation.VerifyAttestation(&p.Attestation, leafPub); err != nil {
		return authority.Scope{}, fmt.Errorf("proof verify: %w", err)
	}

	// Step 4: assert the proof's SigningKeyVersion matches the leaf
	// link's KeyVersion.
	leafVersion := p.DelegationChain[len(p.DelegationChain)-1].KeyVersion
	if p.SigningKeyVersion != leafVersion {
		return authority.Scope{}, fmt.Errorf("proof verify: signing key version %d does not match leaf link version %d",
			p.SigningKeyVersion, leafVersion)
	}

	// Step 5: assert the attestation's claim capability is covered by
	// the intersected scope's Actions. An empty Actions set means
	// unrestricted.
	if err := verifyCapabilityCoverage(p.Attestation, scope); err != nil {
		return authority.Scope{}, err
	}

	return scope, nil
}

// verifyRootLink verifies the first delegation link's ParentSignature
// against the supplied root public key. A failure means the verifier
// supplied the wrong root anchor (ErrWrongRootKey).
func verifyRootLink(link authority.DelegationLink, rootPub crypto.PublicKey) error {
	rootAlg, err := signature.AlgorithmForPublicKey(rootPub)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWrongRootKey, err)
	}
	if link.Algorithm != rootAlg {
		return fmt.Errorf("%w: root algorithm %s does not match link algorithm %s",
			ErrWrongRootKey, rootAlg.JOSE(), link.Algorithm.JOSE())
	}
	if len(link.ParentSignature) == 0 {
		return fmt.Errorf("%w: first link has no parent signature", ErrBrokenDelegationChain)
	}

	// Compute the signing hash: CanonicalHash with ParentSignature
	// zeroed. The parentSignature JSON field has omitempty, so a nil
	// slice is omitted — producing the same canonical bytes as the
	// authority-internal signingHash.
	unsigned := link
	unsigned.ParentSignature = nil
	h, err := authority.CanonicalHash(&unsigned)
	if err != nil {
		return fmt.Errorf("proof verify: root link hash: %w", err)
	}
	ok, err := signature.Verify(link.Algorithm, rootPub, link.ParentSignature, h[:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWrongRootKey, err)
	}
	if !ok {
		return fmt.Errorf("%w: root key does not verify first link signature", ErrWrongRootKey)
	}
	return nil
}

// verifyCapabilityCoverage asserts that the attestation's claim
// capability is covered by the intersected scope's Actions set. The
// claim's capability is carried in claim.Schema — the action the
// attestation authorizes. An empty Actions set means unrestricted;
// any capability is covered.
func verifyCapabilityCoverage(att attestation.Attestation, scope authority.Scope) error {
	if len(scope.Actions) == 0 {
		// Unrestricted — no capability constraint.
		return nil
	}
	claim := att.Claim
	if claim == nil {
		return fmt.Errorf("proof verify: attestation claim is nil")
	}
	capability := claim.Schema
	for _, a := range scope.Actions {
		if a == capability {
			return nil
		}
	}
	return fmt.Errorf("%w: claim capability %q not in scope actions %v",
		ErrCapabilityNotCovered, capability, scope.Actions)
}
