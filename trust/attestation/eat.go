package attestation

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/bperin/trust/canonical"
	"github.com/bperin/trust/credential"
	"github.com/bperin/trust/evidence"
	"github.com/bperin/trust/signature"
)

// Sentinel errors returned by SignAttestation and VerifyAttestation.
// Check them with errors.Is.
var (
	// ErrTamperedAttestation is returned by VerifyAttestation when the
	// stored Signature does not verify against the recomputed canonical
	// hash under the leaf key — the attestation's content has been
	// modified after signing, or the wrong same-algorithm key was
	// supplied. A failed signature verification is indistinguishable
	// from a tampered payload at the signature layer.
	ErrTamperedAttestation = errors.New("attestation: tampered or signature mismatch")

	// ErrWrongKey is returned by VerifyAttestation when the supplied
	// leaf public key does not match the attestation's declared
	// Algorithm — a key/algorithm mismatch, the algorithm-confusion
	// defense. A key of a different algorithm cannot have produced the
	// stored Signature.
	ErrWrongKey = errors.New("attestation: leaf key does not match algorithm")

	// ErrMissingAuthorityRef is returned by VerifyAttestation when
	// AuthorityRef is the zero [32]byte. An attestation must bind to the
	// authority that authorized its signing key; a zero ref is an
	// unrooted attestation.
	ErrMissingAuthorityRef = errors.New("attestation: missing authority reference")
)

// Attestation is a signed claim envelope with authority/delegation
// references and a canonical-hash identity. The leaf signing key —
// derived from the delegation chain, never the root key — signs the
// canonical hash of the unsigned attestation. The canonical hash is
// the attestation's identity: identical content yields an identical
// hash, and a single modified byte changes it.
//
// The signing algorithm is derived from the leaf key at signing time
// via signature.AlgorithmForPrivateKey and stored in Algorithm. The
// registered algorithms and their governing standards are:
//
//   - ed25519      [RFC 8037]; [FIPS 186-5]
//   - secp256k1    [SEC 2 v2]; [RFC 6979]; [EIP-2]
//   - ecdsa-p256   [FIPS 186-4] (P-256)
//   - ecdsa-p384   [FIPS 186-4] (P-384)
//   - rsa-pss      [RFC 8017] (PKCS#1 v2.2, PSS)
//   - rsa-pkcs1v15 [RFC 8017] §8.2
//
// Root keys never sign attestations — only the leaf signing key.
// SignAttestation accepts the leaf key; the package does not enforce
// "not root" (that is the caller's responsibility). No private key
// custody: SignAttestation takes a crypto.PrivateKey and returns.
type Attestation struct {
	// Claim is the signed versioned claim. It must not be nil for a
	// well-formed attestation.
	Claim *credential.VersionedClaim `json:"claim"`

	// Issuer identifies the attestation issuer — a DID or UUID.
	Issuer string `json:"issuer"`

	// SigningKeyID references the leaf signing key in the delegation
	// chain. It is an application lookup key, not interpreted here.
	SigningKeyID string `json:"signingKeyId"`

	// SigningKeyVersion is the key version the attestation was signed
	// under. It corresponds to the leaf link's KeyVersion in the
	// delegation chain.
	SigningKeyVersion uint64 `json:"signingKeyVersion"`

	// AuthorityRef is the canonical hash of the delegation chain (or
	// root authority reference) that authorizes the signing key.
	// VerifyAttestation requires it to be non-zero.
	AuthorityRef [32]byte `json:"authorityRef"`

	// DelegationChainHash is the canonical hash of the full delegation
	// chain. It is carried by the proof and referenced here so the
	// attestation binds to the chain that authorized its key.
	DelegationChainHash [32]byte `json:"delegationChainHash"`

	// Evidence carries content-addressed references to supporting
	// evidence for the claim.
	Evidence []evidence.EvidenceRef `json:"evidence,omitempty"`

	// IssuedAt is when the attestation was produced.
	IssuedAt time.Time `json:"issuedAt"`

	// NotBefore is the start of the attestation's validity window.
	NotBefore time.Time `json:"notBefore"`

	// NotAfter is the end of the attestation's validity window.
	NotAfter time.Time `json:"notAfter"`

	// Status is the attestation lifecycle state: "active" or "revoked".
	Status string `json:"status"`

	// Algorithm is the signature.Algorithm of the leaf key that
	// produced Signature. SignAttestation derives it from the signer;
	// VerifyAttestation requires it to match the supplied leaf key.
	Algorithm signature.Algorithm `json:"algorithm"`

	// Signature is the leaf key's signature over the canonical hash of
	// the unsigned attestation (every field except Signature). It is
	// excluded from the canonical hash so the identity is stable
	// across signing.
	Signature []byte `json:"signature,omitempty"`
}

// CanonicalHash returns the attestation's identity: the [FIPS 180-4]
// SHA-256 digest of the [RFC 8785] JCS-canonical JSON encoding of the
// attestation with the Signature field zeroed. Identical content
// produces an identical hash; a single differing byte in any field
// changes the identity. The Signature is excluded so the identity is
// independent of the signature itself — the digest the leaf key signs.
func CanonicalHash(att *Attestation) ([32]byte, error) {
	if att == nil {
		return [32]byte{}, fmt.Errorf("attestation: nil attestation")
	}
	// Hash the unsigned form: project onto a shallow copy with the
	// Signature zeroed so the identity is independent of the signature.
	// The copy shares the Claim pointer and Evidence slice, which are
	// only read during canonicalization.
	wire := *att
	wire.Signature = nil
	return canonical.CanonicalHash(&wire)
}

// SignAttestation signs att with the leaf signing key: it derives the
// algorithm via signature.AlgorithmForPrivateKey, canonicalizes the
// attestation (Signature zeroed), computes the canonical hash, signs
// the hash via signature.Sign, and stores the result in att.Signature
// and the algorithm in att.Algorithm.
//
// signer is a trust private key (crypto.PrivateKey — the same
// parameter convention as authority.SignLink and identity.Sign; the
// trust key types deliberately do not implement crypto.Signer). It is
// the leaf signing key derived from the delegation chain, never the
// root key. The package takes no custody of the key.
//
// Project algorithms and governing standards:
//
//   - ed25519      [RFC 8037]; [FIPS 186-5]
//   - secp256k1    [SEC 2 v2]; [RFC 6979]; [EIP-2]
//   - ecdsa-p256   [FIPS 186-4] (P-256)
//   - ecdsa-p384   [FIPS 186-4] (P-384)
//   - rsa-pss      [RFC 8017] (PKCS#1 v2.2, PSS)
//   - rsa-pkcs1v15 [RFC 8017] §8.2
func SignAttestation(att *Attestation, signer crypto.PrivateKey) error {
	if att == nil {
		return fmt.Errorf("attestation: nil attestation")
	}
	alg, err := signature.AlgorithmForPrivateKey(signer)
	if err != nil {
		return fmt.Errorf("attestation sign: %w", err)
	}
	att.Algorithm = alg
	att.Signature = nil
	h, err := CanonicalHash(att)
	if err != nil {
		return fmt.Errorf("attestation sign: %w", err)
	}
	sig, err := signature.Sign(alg, signer, h[:])
	if err != nil {
		return fmt.Errorf("attestation sign: %w", err)
	}
	att.Signature = sig
	return nil
}

// VerifyAttestation verifies att against the leaf public key. It is a
// pure function: no I/O, no lookups, no global state.
//
// It requires a non-zero AuthorityRef (ErrMissingAuthorityRef), then
// requires the supplied leaf key's algorithm to match att.Algorithm
// (ErrWrongKey — the algorithm-confusion defense), then recomputes the
// canonical hash of the unsigned attestation and verifies the stored
// Signature against it under the leaf key. A signature verification
// failure returns ErrTamperedAttestation; a key/algorithm mismatch
// returns ErrWrongKey.
//
// leafPub is the leaf signing key's public counterpart — the
// delegation chain's final link PublicKey. Root keys never sign
// attestations; the caller is responsible for supplying the leaf key,
// not the root.
func VerifyAttestation(att *Attestation, leafPub crypto.PublicKey) error {
	if att == nil {
		return fmt.Errorf("attestation: nil attestation")
	}
	// An attestation must bind to the authority that authorized its
	// signing key. Check this before signature verification so a zero
	// ref is reported as ErrMissingAuthorityRef regardless of the
	// signature state.
	var zero [32]byte
	if subtle.ConstantTimeCompare(att.AuthorityRef[:], zero[:]) == 1 {
		return ErrMissingAuthorityRef
	}
	// Algorithm-confusion defense: the supplied key's algorithm must
	// match the attestation's declared Algorithm. A key of a different
	// algorithm cannot have produced the stored Signature.
	pubAlg, err := signature.AlgorithmForPublicKey(leafPub)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWrongKey, err)
	}
	if pubAlg != att.Algorithm {
		return fmt.Errorf("%w: key algorithm %s does not match attestation algorithm %s",
			ErrWrongKey, pubAlg.JOSE(), att.Algorithm.JOSE())
	}
	// Recompute the canonical hash of the unsigned form and verify the
	// signature against it under the leaf key.
	h, err := CanonicalHash(att)
	if err != nil {
		return fmt.Errorf("attestation verify: %w", err)
	}
	ok, err := signature.Verify(att.Algorithm, leafPub, att.Signature, h[:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWrongKey, err)
	}
	if !ok {
		return ErrTamperedAttestation
	}
	return nil
}
