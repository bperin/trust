package verification

import (
	"crypto"
	"time"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/identity/did"
)

// Inputs carries every object the engine needs to verify an attestation
// offline — public keys and documents only, no private key material.
type Inputs struct {
	// Attestation is the attestation under verification; required.
	Attestation *attestation.Attestation
	// SigningKey is the public leaf key for Attestation.SigningKeyID; required.
	SigningKey crypto.PublicKey
	// Chain is the authority delegation chain ordered leaf to root;
	// required non-empty, and the canonical hash of Chain[0].Authority
	// must equal Attestation.AuthorityRef.
	Chain []AuthorityHop
	// IdentityResolver optionally resolves the root identity's DID document.
	IdentityResolver did.Resolver
	// Evidence optionally supplies evidence payloads keyed by the hex of
	// their evidence.CanonicalHash.
	Evidence map[string][]byte
	// Commitments optionally supplies proofs for the configured
	// CommitmentChecker.
	Commitments []CommitmentProof
	// Now is the evaluation instant; the zero value resolves to
	// time.Now() inside the engine.
	Now time.Time
}

// AuthorityHop is one step of the delegation chain: an authority object
// and the public key that verifies its Proof.
type AuthorityHop struct {
	// Authority is the delegated authority at this hop.
	Authority *authority.Authority
	// PublicKey verifies Authority's Proof.
	PublicKey crypto.PublicKey
}
