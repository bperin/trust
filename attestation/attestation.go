package attestation

import (
	"time"

	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/canonical"
	"github.com/bperin/trust/claim"
	"github.com/bperin/trust/evidence"
	"github.com/bperin/trust/signature"
)

// Attestation is an authority-bound, canonically identified statement:
// it binds an issuer, a signing key, a reference to the
// authority.Authority that authorizes the act, the authority.Capability
// being exercised, a claim.Claim payload, zero or more
// evidence.Evidence references, a validity window, a lifecycle status,
// a signature algorithm, and the signature itself.
//
// The attestation's identity is its canonical hash: the [FIPS 180-4]
// SHA-256 digest of the [RFC 8785] JCS-canonical JSON encoding of every
// field except Signature. The signature signs that digest, so it is
// excluded from the hashed bytes to keep the identity stable across
// signing.
//
// The claim is a named field — never anonymously embedded:
// Attestation.Issuer and Attestation.Validity share the "issuer" and
// "validity" JSON tags with claim.Claim.Issuer and claim.Claim.Validity,
// so embedding would make encoding/json suppress the deeper claim
// fields and drop them from the canonical hash and the JSON round-trip.
//
// An attestation is trustworthy only under dual verification: the
// signature check (the referenced signing key produced Signature over
// the canonical hash) and the authorization check (the referenced
// authority grants the exercised capability, and the claim's scope and
// validity fit inside the authority's) must both pass. Validate checks
// structure only; it performs neither half.
type Attestation struct {
	// Issuer identifies the attestation issuer — a DID. Must be
	// non-empty.
	Issuer string `json:"issuer"`

	// SigningKeyID references the leaf signing key that produced
	// Signature. It is an application lookup key, not interpreted here.
	SigningKeyID string `json:"signingKeyId"`

	// SigningKeyVersion is the key version the attestation was signed
	// under.
	SigningKeyVersion uint64 `json:"signingKeyVersion"`

	// AuthorityRef is the hex encoding of the canonical hash of the
	// authority.Authority that authorizes this attestation. Must be
	// non-empty.
	AuthorityRef string `json:"authorityRef"`

	// Capability is the authority.Capability this attestation exercises.
	// The referenced authority must grant it.
	Capability authority.Capability `json:"capability"`

	// Claim is the claim.Claim payload the attestation signs. Held by
	// value as a named field so its "issuer" and "validity" members
	// survive JSON marshaling alongside the attestation's own.
	Claim claim.Claim `json:"claim"`

	// Evidence holds content-addressed references to supporting
	// material. The canonical form is sorted strictly ascending by
	// evidence.CanonicalHash and dedup-free; Validate rejects an
	// unsorted or duplicated slice rather than normalizing it.
	Evidence []evidence.Evidence `json:"evidence"`

	// IssuedAt is when the attestation was produced.
	IssuedAt time.Time `json:"issuedAt"`

	// Validity bounds the attestation in time. It must sit inside the
	// referenced authority's validity window for authorization to pass.
	Validity authority.Validity `json:"validity"`

	// Status is the attestation's lifecycle state. Reuses
	// authority.Status — the same four-state lifecycle.
	Status authority.Status `json:"status"`

	// Algorithm is the signature.Algorithm of the leaf key that
	// produced Signature. It is part of the hashed bytes; verification
	// requires the supplied leaf key to match it.
	Algorithm signature.Algorithm `json:"algorithm"`

	// Signature is the leaf key's signature over the canonical hash of
	// the unsigned attestation. It is excluded from the canonical hash
	// and omitted from the JSON of an unsigned attestation.
	Signature []byte `json:"signature,omitempty"`
}

// CanonicalEncoding declares the attestation's canonical byte encoding
// per the canonical.EncodingDeclarer interface: canonical.EncodingJSON,
// the JSON Canonicalization Scheme (JCS) per [RFC 8785]. CanonicalHash
// consults this declaration so the encoding selection stays in one
// place.
func (a *Attestation) CanonicalEncoding() canonical.Encoding {
	return canonical.EncodingJSON
}
