// Package claim defines the claim data model: a content-addressed,
// JCS-canonical statement that an attestation signs — the payload of
// the trust chain.
//
// A Claim binds an issuer to a subject under a namespaced claim type,
// carrying an arbitrary JSON-canonicalizable value, an authority.Scope
// narrowing where the claim applies, an authority.Validity window, and
// provenance describing where and how the claim originated. The claim
// type space is open: consumers define ClaimType values in their own
// namespaces — this package predefines none.
//
// # Canonical identity
//
// The claim's identity is the [FIPS 180-4] SHA-256 digest of its
// [RFC 8785] JCS-canonical JSON encoding, computed by CanonicalHash.
// No field is zeroed or excluded: the entire Claim struct is the
// identity. Identical logical claims — regardless of construction
// order — yield identical hashes; a single differing byte in any field
// changes the identity. Unlike authority.CanonicalHash there is no
// proof to exclude: a Claim carries no signature — that is the
// attestation's role.
//
// # JSON tags contract
//
// All fields serialize under the JSON tags declared on the types in
// this package. Scope and Validity are embedded by value — copies, not
// references to shared state. Provenance is a value type with no
// omitempty on any field, so it always serializes in full. Claim.Value
// is any JSON-canonicalizable value: time.Time marshals as RFC 3339
// and []byte as base64 via the encoding/json defaults; non-finite
// numbers, lossy integer literals beyond the IEEE 754 exact-integer
// range, and unmarshalable types are rejected by CanonicalHash.
//
// # Dependency rule
//
// This package imports only canonical (for the encoding declaration
// and canonical hash) and authority (for the Scope and Validity value
// types and ValidateScope). It must never import auth, chain, kms,
// signature, attestation, merkle, or evidence — the isolation test in
// this package enforces that rule.
package claim
