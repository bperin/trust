// Package commitment batches trust objects — authorities, claims,
// attestations, and evidence — into a single [RFC 6962] Merkle
// commitment. Each leaf is the object's canonical hash: the
// [FIPS 180-4] SHA-256 digest of its [RFC 8785] JCS-canonical encoding,
// produced by the trust-object packages' CanonicalHash functions and
// bridged here through the TrustObject adapters.
//
// The package is pure and offline: no I/O, no global state, no
// private-key custody. All operations are safe for concurrent use.
//
// Merkle tree hashing follows [RFC 6962] §2.1 domain-separated
// SHA-256 over leaf data; leaf identity follows [FIPS 180-4] SHA-256
// over canonical bytes. The sentinel error taxonomy lives in errors.go.
package commitment
