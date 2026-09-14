package verification

import (
	"crypto"
	"time"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/identity/did"
)

// Inputs carries every object the engine needs; public keys and documents only, no private keys.
type Inputs struct {
	// Attestation is the attestation under verification; required.
	Attestation *attestation.Attestation
	// SigningKey is the public leaf key for Attestation.SigningKeyID; required.
	SigningKey crypto.PublicKey
	// Chain is the authority chain ordered leaf to root; required non-empty.
	Chain []AuthorityHop
	// IdentityResolver optionally resolves the root identity's DID document.
	IdentityResolver did.Resolver
	// Evidence optionally supplies payloads keyed by evidence canonical-hash hex.
	Evidence map[string][]byte
	// Commitments optionally supplies proofs for the configured CommitmentChecker.
	Commitments []CommitmentProof
	// Now is the evaluation instant; zero resolves to time.Now() in the engine.
	Now time.Time
}

// AuthorityHop is one step of the delegation chain.
type AuthorityHop struct {
	// Authority is the delegated authority at this hop.
	Authority *authority.Authority
	// PublicKey verifies Authority's Proof.
	PublicKey crypto.PublicKey
}
