// Package authority builds and verifies hierarchical delegation
// chains: ordered sequences of signed links running from a root
// trust anchor to a leaf signing key, where each link carries a
// bounded subset of its parent's authority.
//
// A DelegationLink binds a child public key to a key ID, a parent
// authority reference (the canonical hash of the preceding link, or
// zero for the link issued directly by the root anchor), a
// capability set, and scope restrictions across nine dimensions —
// resource, action/capability, organization, geography, channel,
// time, quantity, monetary, and delegation depth — plus a status,
// a monotonic key version, and the parent's signature over the
// canonical link payload.
//
// Scope intersection is enforced at verification time, not just at
// delegation time. VerifyChain re-intersects the full chain
// top-to-bottom so a child can never exceed parent scope even if a
// delegation record was malformed or over-granted; the returned
// Scope is the tightest bound implied by every link.
//
// Key versions are non-decreasing within a presented chain. Stale
// detection — a newer version issued elsewhere — is an application
// concern surfaced through the optional VerifyOptions.LatestVersions
// map.
//
// Capabilities are canonical strings (e.g., "product.attest",
// "revoke", "delegate") — not a free-form grammar.
//
// Every signed payload is the [FIPS 180-4] SHA-256 canonical hash of
// the link's [RFC 8785] JCS projection (public keys serialize as
// [RFC 7517] JWKs, algorithms as [RFC 7518] JOSE names). Signing and
// verification dispatch through trust/signature, so all registered
// algorithms are supported: Ed25519 [RFC 8032]; [FIPS 186-5]
// (default), secp256k1 [SEC 2 v2]; [RFC 6979]; [EIP-2], ECDSA P-256
// and P-384 [FIPS 186-4], and RSA-PSS / RSA PKCS#1 v1.5 [RFC 8017].
//
// The package holds no private key material and no state. SignLink
// takes the caller's crypto.PrivateKey (the trust key types —
// consistent with identity.Sign and attestation.Issue), and
// VerifyChain is a pure function of the chain and the root public
// key: no I/O, no lookups, no global state.
package authority
