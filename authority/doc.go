// Package authority defines the authority data model: a typed object
// binding a subject (a DID), a set of capabilities, a scope, a validity
// window, delegation constraints, a lifecycle status, and a
// cryptographic proof.
//
// An Authority is the unit of delegated power in the trust model. A
// root authority (Parent == nil) is self-asserted by its subject; a
// delegated authority carries a Parent reference to the canonical hash
// of the authority it was delegated from, narrowed by its
// DelegationConstraints.
//
// # Canonical identity
//
// The authority's identity is the [FIPS 180-4] SHA-256 digest of its
// canonical encoding. Authority implements canonical.EncodingDeclarer
// and declares canonical.EncodingJSON — the JSON Canonicalization
// Scheme (JCS) per [RFC 8785]. CanonicalHash computes the digest over a
// shallow copy of the authority with Proof.Signature zeroed: the
// signature is excluded so the identity is stable across signing, while
// Proof.Algorithm and Proof.KeyID remain part of the hashed bytes.
//
// # JSON tags contract
//
// All fields serialize under the JSON tags declared on the types in
// this package. Scope dimensions and Parent use omitempty so a
// zero-value Scope serializes to {} and a root authority omits the
// parent field. Status serializes as a plain JSON number (1-4) via the
// encoding/json default — there is deliberately no custom marshaler.
//
// # Dependency rule
//
// This package imports only canonical (for the encoding declaration and
// canonical hash) and signature (for the Algorithm type carried by
// Proof). It must never import auth, chain, or kms — the isolation test
// in this package enforces that rule.
package authority
