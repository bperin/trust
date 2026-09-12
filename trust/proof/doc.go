// Package proof carries a self-contained attestation proof for offline
// verification — a signed attestation, the full delegation chain from the
// root anchor to the leaf signing key, key versions, and the advisory
// scope intersection. A verifier supplies only the root public key;
// everything else comes from the proof bytes. No database, no RPC, no
// revocation list, no global state.
//
// The proof model is: Identity → Authority → Delegation → Claim →
// Attestation → Proof. The proof object bundles the attestation and the
// delegation chain so cryptographic verification is a pure function of
// the proof and the root public key.
//
// VerifyProof is a pure function. It performs no I/O, no network calls,
// no database lookups, and reads no global state. Scope intersection is
// re-computed at verification time via authority.VerifyChain; the cached
// IntersectedScope field is advisory only and is never trusted.
//
// Key versions are monotonic (non-decreasing) within the presented
// chain. The attestation is signed by the leaf key derived from the
// chain, never the root. The proof asserts that the SigningKeyVersion
// matches the leaf link's KeyVersion.
//
// Every signed payload is the [FIPS 180-4] SHA-256 canonical hash of
// the object's [RFC 8785] JCS projection. Signing and verification
// dispatch through trust/signature, so all registered algorithms are
// supported: Ed25519 [RFC 8037]; [FIPS 186-5] (default), secp256k1
// [SEC 2 v2]; [RFC 6979]; [EIP-2], ECDSA P-256 and P-384 [FIPS 186-4],
// and RSA-PSS / RSA PKCS#1 v1.5 [RFC 8017].
//
// The package holds no private key material and no state. BuildProof
// takes the caller's attestation and chain and returns a Proof value;
// VerifyProof takes the Proof and the root public key and returns the
// intersected scope.
package proof
