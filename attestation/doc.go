// Package attestation implements the authority-bound Attestation: a
// single, canonically encoded, self-describing object that binds an
// issuer, a signing key, a reference to the authority.Authority that
// authorizes the act, the authority.Capability being exercised, a
// claim.Claim payload, evidence.Evidence references, a validity window,
// a lifecycle status, a signature algorithm, and the signature itself.
//
// The defining invariant is dual verification: an attestation is
// trustworthy only when both the signature check — the referenced
// signing key produced Signature over the canonical hash — and the
// authorization check — the referenced authority grants the exercised
// capability, and the claim's scope and validity fit inside the
// authority's — pass. Neither check alone is sufficient.
//
// The attestation's identity is its canonical hash: the [FIPS 180-4]
// SHA-256 digest of the [RFC 8785] JCS-canonical JSON encoding of every
// field except Signature. JSON/JCS is the identity encoding — there is
// one struct and one canonical form. The EAT/CBOR path (eat_cbor.go,
// [RFC 8392] CWT claims inside [RFC 9052] COSE_Sign1) is an optional
// transport of the same attestation, not a parallel model.
//
// Dependency rule: attestation imports none of auth/, chain/, kms/,
// delegation/, or merkle/. It composes the lower-level trust packages
// authority, claim, evidence, signature, and canonical only.
package attestation
