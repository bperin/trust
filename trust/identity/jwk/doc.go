// Package jwkutil implements [RFC 7517] JSON Web Key (JWK) marshal and
// unmarshal for the trust key types. It converts to and from the
// concrete key types in trust/crypto/* without introducing any new
// cryptographic primitives — all keys are built with the existing
// constructors.
//
// The package name is jwkutil (rather than jwk) to avoid import
// collisions with the many third-party JWK libraries and with
// crypto/x509-style packages that consumers may also import.
//
// # Standards
//
// Marshal and unmarshal follow:
//
//   - [RFC 7517] — JSON Web Key (JWK) structure and the JWK Set.
//   - [RFC 7518] — JSON Web Algorithms (JWA): the "alg" identifiers and
//     the per-key-type member definitions (EC §6.2, RSA §6.3, OKP via
//     [RFC 8037]).
//   - [RFC 8037] — Key type "OKP" for Ed25519 and X25519. For an OKP
//     key, "crv" is "Ed25519" or "X25519", "x" is the base64url public
//     key, and "d" (private keys only) is the base64url private key.
//     Ed25519 signs with the "EdDSA" algorithm.
//   - [RFC 8812] — secp256k1 in JOSE: "kty" is "EC", "crv" is
//     "secp256k1", and the algorithm identifier is "ES256K". The "x"
//     and "y" coordinates are the uncompressed point coordinates, each
//     exactly 256 bits with leading zeros preserved.
//
// # Encoding
//
// All key material is base64url-encoded without padding per [RFC 7515]
// §2 (encoding/base64 RawURLEncoding). Big integers (EC coordinates,
// RSA modulus and exponents) are encoded as the big-endian byte
// representation of the integer, base64url-encoded.
//
// # Security
//
// The "alg" member is pinned at unmarshal time and validated against a
// per-key-type whitelist; "alg":"none" is always rejected, and an
// "alg" that does not match the key type is rejected. The package never
// trusts an incoming "alg" to select a key type — it derives the
// expected algorithm from "kty" and "crv" and only accepts a matching
// "alg".
//
// Duplicate member names in a JWK object are rejected (a JWK is a JSON
// object, and [RFC 8255] §4 states that object member names SHOULD be
// unique; this package treats duplicates as an error to prevent
// last-value-wins ambiguity in security-sensitive material).
//
// Private keys are never logged by this package. Marshal output is
// returned to the caller; the caller is responsible for handling it
// securely. Tests never print the "d" member.
package jwkutil
