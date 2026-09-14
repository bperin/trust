// Package evidence defines the evidence data model: a content-addressed,
// JCS-canonical reference to supporting material — an identifier, a
// content hash, a media type, a locator, provenance, and metadata.
//
// An Evidence is a reference, not the material itself: ContentHash binds
// the reference to a specific byte sequence and Locator says where the
// material may be retrieved, but this package never fetches, stores, or
// interprets the content.
//
// # Canonical identity
//
// The evidence's identity is the [FIPS 180-4] SHA-256 digest of its
// [RFC 8785] JCS-canonical JSON encoding — the entire struct, with no
// field excluded. Evidence implements canonical.EncodingDeclarer and
// declares canonical.EncodingJSON. CanonicalHash is distinct from
// ContentHash: ContentHash is the stored digest of the external material
// the evidence points at, while CanonicalHash is the computed identity of
// the Evidence value itself — ContentHash is one of the fields that
// identity covers.
//
// # JSON tags contract
//
// All fields serialize under the JSON tags declared on Evidence and
// Provenance. Metadata is map[string]any with omitempty — JCS sorts
// object keys by UTF-16 code unit, so map iteration order never affects
// the canonical bytes. Provenance is a value type with no omitempty: its
// fields are always present in the canonical form. ContentHash is []byte
// and marshals as base64 via the encoding/json default.
//
// # Dependency rule
//
// This package imports only canonical (for the encoding declaration and
// the canonical hash). It must never import authority, auth, chain, kms,
// signature, attestation, merkle, or claim — the isolation test in this
// package enforces that rule.
package evidence
