// Package canonical produces deterministic canonical byte encodings for Go
// values and the SHA-256 canonical hash that serves as the identity of every
// trust object.
//
// Two canonical encodings are supported:
//
//   - JSON Canonicalization Scheme (JCS) per [RFC 8785] — object property
//     names sorted by UTF-16 code unit, numbers serialized in the ECMAScript
//     Number::toString shortest round-trip form, and no insignificant
//     whitespace.
//   - Deterministically encoded CBOR per [RFC 8949] §4.2.1 — shortest-form
//     integer and length arguments, definite-length items only, and map keys
//     sorted bytewise lexicographic on their encoded form.
//
// CanonicalHash returns the [FIPS 180-4] SHA-256 digest of the canonical
// bytes. Two implementations that agree on the canonical bytes agree on the
// object's identity, which is what makes signatures and content-addressed
// storage verifiable across platforms.
//
// All functions in this package are pure: no I/O, no logging, and no mutable
// state.
//
// Standards referenced:
//   - [RFC 8785] — JSON Canonicalization Scheme (JCS)
//   - [RFC 8949] §4.2.1 — Deterministically Encoded CBOR
//   - [FIPS 180-4] — SHA-256
package canonical
