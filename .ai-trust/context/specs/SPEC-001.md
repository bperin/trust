# SPEC-001: trust — Cryptographic Trust Core

<!-- Template hierarchy: SPEC-NNN → plans/PLAN-NNN.md → tasks/TASK-NNN.md -->
<!-- This SPEC describes WHAT and WHY. The Architect determines HOW in plans/PLAN-NNN.md. -->

## Supersedes

- Supersedes: the original combined SPEC-001 (Trust & Security Platform — Core Consolidation)
- Reason: the combined spec was too broad (26 packages across 3 modules) and contained
  architectural errors (SIWE/did:pkh dependency violations, missing Keccak-256, missing
  attestation canonicalization). Split into SPEC-001 (trust), SPEC-002 (auth), SPEC-003
  (chain) per the architecture guidance: "establish the cryptographic and identity pipeline
  first, then add provider-specific integrations as adapters."
- Superseded by: none

## What

A pure cryptographic foundation providing hashing, signing, encryption, key derivation,
identity representation, Merkle proofs, verifiable credentials, and signed attestations.
The core has zero dependencies on any application, authentication provider, blockchain, or
RPC provider. It consolidates Ed25519 attestation signing and HKDF key derivation currently
in `trakt2`, and provides the EVM-address-recovery and Keccak-256 primitives that both
`auth` (for SIWE/did:pkh) and `chain` (for EVM/EIP-712) depend on without importing each
other.

## Why

- **Eliminate duplicated crypto code.** `trakt2` ships hand-rolled Ed25519
  `RootKey`/`SignAttestation`/`VerifyAttestation` and `DeriveChildKey` (HKDF-SHA256) in
  `internal/infra/security/keys.go`. `ghost-protocol` ships a hand-rolled HS256 JWT
  issuer in `internal/security/jwt.go` that belongs in `auth` (SPEC-002) but whose
  HMAC-SHA256 signing primitive belongs here. Every new project re-implements these.
- **Provide EVM primitives in the core so `auth` and `chain` don't cross-depend.** SIWE
  verification (`auth`) and EVM transaction signing (`chain`) both need secp256k1 public-key
  recovery, Keccak-256, and Ethereum address derivation. If these live only in `chain`,
  then `auth` must import `chain` — violating the dependency rule. They must live in `trust`.
- **Establish a shared identity/proof/attestation layer.** Web3 and AI-agent projects need
  a unified notion of identity, proof, and attestation that is independently verifiable
  without any provider or chain.
- **Cryptographic soundness.** The original combined spec left attestation canonicalization,
  AEAD nonce management, and signature malleability undefined. This spec defines them.

## Desired Behavior

### Hashing

1. An application can hash data with SHA-256, SHA-3 (FIPS 202), Keccak-256 (Ethereum's
   pre-FIPS variant — distinct from SHA-3), and BLAKE3 through a consistent interface.
2. Keccak-256 is explicitly distinguished from SHA-3 in documentation and API naming,
   because Ethereum address derivation, EIP-712, and EIP-191 all require Keccak-256, not
   FIPS SHA-3.

### Key Derivation

3. An application can derive child keys from a root secret using HKDF-SHA256 with an info
   string (replacing `trakt2`'s `DeriveChildKey`).

### Authenticated Encryption

4. An application can encrypt and decrypt with AES-256-GCM and XChaCha20-Poly1305 through
   a consistent interface.
5. Nonce management is handled by the library, not the caller: a random nonce is generated
   per message, prefixed to the ciphertext, and the output format is `nonce || ciphertext`.
   The library enforces nonce uniqueness per key and rejects caller-supplied nonces unless
   an explicit counter-mode API is used.
6. The version/type identifier of the encrypted object is bound as Additional Authenticated
   Data (AAD) so ciphertext cannot be replayed against a different object type.

### Envelope Encryption

7. An application can wrap data-encryption keys (DEKs) with a key-encryption key (KEK)
   using AES-KW (RFC 3394) or an HPKE-based wrap, keeping KEKs and DEKs separate as the
   architecture spec requires.

### Key Agreement

8. An application can perform X25519 ECDH to derive a shared secret between two parties.

### Signing — Ed25519

9. An application can generate Ed25519 keypairs, sign arbitrary messages, and verify
   signatures (replacing `trakt2`'s `RootKey`/`SignAttestation`/`VerifyAttestation`).

### Signing — secp256k1 (EVM-compatible)

10. An application can generate secp256k1 keypairs, sign, and verify.
11. Signatures are canonical: low-s form, RFC 6979 deterministic nonce derivation, and
    malleability checks. Two valid signatures must not exist for the same digest.
12. An application can recover a public key from a secp256k1 signature and digest, and
    derive the corresponding Ethereum/EVM address from a public key. This is the primitive
    that `auth` (SIWE) and `chain` (wallet) both consume without importing each other.

### Signing — RSA and ECDSA (NIST P-256/P-384)

13. An application can sign and verify with RSA (RSASSA-PKCS1-v1_5 and RSASSA-PSS) and
    ECDSA on P-256/P-384. These are required for X.509 certificate verification, OIDC ID
    token validation (JWKS), and JWS interoperability — none of which Ed25519 or
    secp256k1 alone can cover.

### Secure Random

14. An application can generate cryptographically secure random bytes of arbitrary length.
    This is a raw primitive only — URL-safe token generation, hex nonces, and numeric
    confirmation codes are auth-layer concerns (SPEC-002), not trust concerns.

### Identity — DID

15. An application can parse, represent, and resolve W3C DIDs through a resolver
    interface, including `did:pkh` for blockchain-account DIDs.
16. A `did:pkh` for a known Ethereum address round-trips through parse, resolve, and
    verify using the secp256k1 recovery and Keccak-256 primitives in this module —
    without importing `chain`.

### Identity — X.509

17. An application can parse and verify X.509 certificates with a defined verification
    policy: trusted root anchors, path validation, name constraints, EKU checks, expiry
    enforcement, and revocation checking (CRL or OCSP).

### Identity — JWK / COSE / JOSE

18. An application can serialize and deserialize keys in JWK and COSE formats, and
    produce/consume JWS structures. This is the interoperability bridge between
    `trust` key types and OIDC/JWT (consumed by `auth`) and attestation proof formats.

### Merkle Trees

19. An application can construct a Merkle tree from leaf data, generate inclusion proofs,
    and verify those proofs against a known root. Proofs for absent leaves must fail
    verification.

### Verifiable Credentials

20. An application can build W3C Verifiable Credentials binding an issuer to a subject
    over a set of claims.

### Attestations

21. An application can issue and verify signed attestations binding an issuer identity to
    a subject identity over a payload hash at a point in time.
22. The signing input is canonicalized before signing: fields are serialized in a
    deterministic order (sorted JSON or CBOR deterministic encoding), the signature field
    is excluded from the signing input, and a protocol-specific domain/context string is
    included to prevent cross-protocol signature reuse.
23. An attestation carries `validFrom` and `validUntil` timestamps so verifiers can reject
    expired attestations, and a status mechanism (e.g., a revocation list or status list
    credential) so issuers can revoke attestations.
24. An attestation can carry an opaque anchor reference (a content hash or Merkle root
    plus chain/network identifier) without the core knowing how to verify the anchor.
    Anchor verification is orchestrated by `chain` (SPEC-003); `trust` only stores and
    serializes the reference.

### Serialization

25. Every serialized security object (attestation, credential, encrypted blob, key, proof)
    carries a version and type identifier to permit future protocol evolution.

### Security Hygiene

26. Token, tag, and hash comparisons use constant-time comparison (`crypto/subtle`).
27. Private keys are never logged, serialized accidentally, or exposed through
    `String()`/`Format()` methods. Private key types implement redaction.
28. The module documents that Go's garbage collector prevents guaranteed secure erasure
    of key material in memory, and recommends minimizing key lifetime where practical.

## Scope

### In Scope

- `trust` module with packages: `crypto/hash`, `crypto/aead`, `crypto/envelope`,
  `crypto/hkdf`, `crypto/ed25519`, `crypto/secp256k1`, `crypto/rsa`, `crypto/ecdsa`,
  `crypto/x25519`, `crypto/rand`, `identity/did`, `identity/didpkh`, `identity/x509`,
  `identity/jwk`, `merkle`, `signature`, `credential`, `attestation`.
- Core abstractions: `Signer`, `Verifier`, `Hasher`, `Identity`, `Credential`,
  `Attestation`, `MerkleProof`, `AnchorRef`.
- secp256k1 public-key recovery and EVM address derivation (consumed by `auth` and
  `chain`).
- Keccak-256 hashing (consumed by `auth` for SIWE/did:pkh and by `chain` for EIP-712/EVM).
- JWK/COSE/JOS key serialization.
- Test vectors for all cryptographic operations.
- Canonicalization and domain separation for attestation signing.

### Out of Scope

- JWT issuance, validation, or claim extraction (SPEC-002, `auth`).
- Password hashing, session management, OAuth, OIDC, WebAuthn, SIWE flows (SPEC-002,
  `auth`).
- URL-safe token generation, numeric confirmation codes, hex nonces (SPEC-002, `auth`).
- EIP-712 typed-data hashing and signing (SPEC-003, `chain` — uses `trust`'s Keccak-256
  and secp256k1).
- EVM transaction construction, RLP encoding, contract interaction (SPEC-003, `chain`).
- On-chain anchor verification (SPEC-003, `chain` — `trust` stores the `AnchorRef`,
  `chain` verifies it).
- RPC provider adapters, QuickNode integration (SPEC-003, `chain`).
- Application-specific user databases, billing, or multi-tenant logic.
- A hosted/managed service or control plane.
- Agent protocol implementations (A2A, etc. — live above `trust`).

## Constraints

- `trust` must never import `auth` or `chain`. It is pure crypto with no HTTP, no DB, no
  application logic.
- No reflection-based runtime DI (uber/fx, uber/dig). Explicit constructor composition.
- No interface inflation: expose concrete structs; define interfaces near the consumer
  only when multiple implementations exist.
- Never invent cryptographic algorithms or serialization formats. Favor established
  standards (NIST FIPS, RFC 7518/8037, W3C VC/DM, W3C DID, RFC 6979, RFC 3394).
- Private keys must never be logged, serialized accidentally, or exposed via debugging.
- All externally supplied signatures, certificates, credentials, and proofs are untrusted
  input and must be validated before use. Verification failures fail closed.
- Every serialized security object carries a version/type identifier.
- Constant-time comparison for all security-sensitive comparisons.
- **Godoc standard citations:** every exported declaration (function, type, method,
  constant, variable) must cite the governing standard in its Godoc comment. Format:
  `// FooBar implements [RFC 7519] section 5.1.` with the standard identifier (RFC
  number, NIST FIPS publication, EIP number, W3C spec name, etc.) inline. If a function
  implements a test vector from a standard, cite the specific section. If no formal
  standard exists (e.g., BLAKE3), cite the specification document and its authors. The
  common-sense rationale ("why this exists, why we use it") follows the citation.

### Dependency Matrix

The "stdlib-first" constraint acknowledges these required non-stdlib dependencies:

| Primitive | Dependency | Rationale |
|-----------|------------|-----------|
| Keccak-256 | `golang.org/x/crypto/sha3` | Not in stdlib; required for all EVM work |
| secp256k1 | `github.com/decred/dcrd/dcrec/secp256k1/v4` | stdlib only has NIST curves |
| BLAKE3 | `lukechampine.com/blake3` | Not in stdlib or x/crypto |
| XChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` | Extended-nonce variant not in stdlib |
| AES-KW (RFC 3394) | `golang.org/x/crypto/cryptobyte` or manual | Not in stdlib |
| Ed25519, X25519, AES-GCM, RSA, ECDSA, HKDF, SHA-256, SHA-3 | Go stdlib | No third-party needed |

## Success Criteria

1. `go build ./...` succeeds from `trust/`.
2. `go vet ./...` is clean from `trust/`.
3. `go test ./...` passes from `trust/` with no skipped tests. `go test -race ./...`
   also passes.
4. `govulncheck ./...` reports no known vulnerabilities in `trust/` dependencies.
4. SHA-256, SHA-3, Keccak-256, and BLAKE3 each produce the expected digest for a known
   NIST/test vector. Keccak-256 of empty input is
   `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.
5. HKDF-SHA256 derives a 32-byte key from a known input/salt/info triple matching RFC 5869
   Test Case 1.
6. AES-256-GCM encrypts a known plaintext with a known key and random nonce, and decryption
   recovers the plaintext. Tampering any byte of the ciphertext or AAD causes decryption to
   fail.
7. XChaCha20-Poly1305 encrypts and decrypts round-trip, and a modified nonce on decryption
   causes failure.
8. Envelope encryption wraps a DEK with a KEK via AES-KW, and unwrapping recovers the
   original DEK. A wrong KEK causes unwrapping to fail.
9. X25519 ECDH produces a shared secret matching RFC 7748 Section 6.1 test vector.
10. Ed25519 signs and verifies a known message, matching RFC 8032 test vector 1. A
    modified signature or message fails verification.
11. secp256k1 signs a known digest, and the signature is canonical (low-s). A high-s
    signature is rejected on verification. RFC 6979 deterministic nonce produces the same
    signature for the same key+message.
12. secp256k1 public-key recovery from a signature+digest recovers the correct public key
    for a known test vector. Ethereum address derivation from that public key matches the
    expected `0x...` address.
13. RSA-PSS signs and verifies a known message with a 2048-bit key. ECDSA P-256 signs and
    verifies a known message. Both match NIST test vectors.
14. Secure random generation produces 32 bytes that are not all zero and not equal across
    two calls.
15. A `did:pkh` for a known Ethereum address parses to the correct DID string, and a
    signature over a challenge verifies using the secp256k1 recovery + Keccak-256
    primitives in this module — without importing `chain`.
16. X.509 verification accepts a valid certificate chain against a trusted root and rejects
    an expired certificate, a wrong-EKU certificate, and a revoked certificate.
17. A Merkle tree built from 4 known leaves produces inclusion proofs that verify against
    the computed root. A proof for a leaf not in the tree fails verification. A proof
    against the wrong root fails.
18. An attestation issued with a known Ed25519 key verifies successfully. Modifying any
    field (issuer, subject, timestamp, payload hash, claims) causes verification to fail.
    The signature is bound to a domain string — the same signature does not verify under a
    different domain.
19. An attestation with `validUntil` in the past is rejected by verification. A revoked
    attestation (status list indicates revoked) is rejected.
20. Every serialized attestation, credential, and encrypted blob carries a visible
    version and type field in its JSON/CBOR output.
21. `crypto/subtle.ConstantTimeCompare` is used in all token/tag/hash comparison code paths
    (verifiable by grep — no `==` or `bytes.Equal` on security-sensitive values).
22. No private key type has a `String()` or `Format()` method that returns the raw key
    bytes (verifiable by grep).

## Standards & References

Every capability in this spec is governed by a formal standard or specification. The
Godoc comments on the implementing code must cite these. The "why" column is the
plain-language rationale — what problem the primitive solves in this platform.

### Hashing

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| SHA-256 | NIST FIPS 180-4 (Secure Hash Standard) | Universal hash — JWT HMAC, Merkle leaves, content hashes. Every verifier on earth supports it. |
| SHA-3 (Keccak-f) | NIST FIPS 202 (SHA-3 Standard) | SHA-2 alternative for environments requiring sponge-based hashing. Not the same as Keccak-256. |
| Keccak-256 | EIP-191 §2; original Keccak team submission (pre-FIPS) | Ethereum's hash — address derivation, EIP-712, EIP-191. Not FIPS SHA-3 (NIST changed the padding). Without this, no EVM interop. |
| BLAKE3 | BLAKE3 Specification (BLAKE3-team, 2020) | Fastest modern hash for large-data Merkle trees and content-addressed storage. Not a NIST standard but well-reviewed and widely adopted. |

### Key Derivation

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| HKDF-SHA256 | RFC 5869 (HMAC-based Extract-and-Expand KDF) | Derives scoped child keys from a root secret. Used for per-agent, per-product, per-session key separation without a KMS. |

### Authenticated Encryption

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| AES-256-GCM | NIST SP 800-38D (Galois/Counter Mode); AES: FIPS 197 | Hardware-accelerated AEAD on every modern CPU. The default for encrypting data at rest. |
| XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha; ChaCha20-Poly1305: RFC 8439 | 24-byte nonce means random nonces are safe without a counter — no nonce-reuse risk. Preferred for envelope-encrypted DEKs and any context where nonce management is hard. |
| AEAD nonce management | NIST SP 800-38D §8.2.1 (uniqueness requirement) | Nonce reuse with AES-GCM leaks the key. The library must enforce this, not the caller. |

### Envelope Encryption

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| AES-KW (key wrap) | RFC 3394 (AES Key Wrap Algorithm) | Wraps DEKs with KEKs. NIST-approved, simple, no nonce. Used for at-rest key encryption. |
| HPKE (optional) | RFC 9180 (Hybrid Public Key Encryption) | Key wrapping for public-key recipients. Used when the KEK is a public key, not a symmetric key. |

### Key Agreement

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| X25519 | RFC 7748 (Elliptic Curves for Security) | Fast, constant-time ECDH with no NIST-curve concerns. Used for ephemeral session key agreement between two parties. |

### Signing

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| Ed25519 | RFC 8037 (CFRG EdDSA); FIPS 186-5 | Deterministic, fast, small signatures. The default for attestation signing and agent identity. No nonce-reuse risk. |
| secp256k1 | SEC 2 v2 (Recommended Elliptic Curve Domain Parameters) | The curve used by Bitcoin and Ethereum. Required for EVM wallet signing, SIWE, and did:pkh. |
| secp256k1 deterministic nonce | RFC 6979 (Deterministic DSA/ECDSA) | Eliminates nonce-reuse catastrophic failures (e.g., the PlayStation 3 ECDSA hack). Same key+message always produces the same signature. |
| secp256k1 low-s canonicalization | BIP-62 (Dealing with Malleability); EIP-2 (Homestead) | Without low-s, two valid signatures exist for the same digest. Ethereum rejects high-s. We enforce it at the primitive level. |
| secp256k1 public-key recovery | SEC 1 v2 §4.3.3 (Elliptic Curve Cryptography) | Recovers a public key from a signature+digest. The basis of SIWE verification and Ethereum transaction sender recovery. |
| RSA (PKCS1-v1_5, PSS) | RFC 8017 (PKCS #1 v2.2); FIPS 186-4 | Required for X.509 certificate verification and OIDC ID tokens (JWKS). Most enterprise PKI uses RSA. |
| ECDSA P-256/P-384 | FIPS 186-4; ANSI X9.62 | Required for X.509 and OIDC/JWKS interop. NIST curves are the default in enterprise PKI and cloud KMS. |

### Secure Random

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| CSPRNG | NIST SP 800-90A (Recommendation for Random Number Generation) | Every key, nonce, and token starts here. Go's `crypto/rand` uses the OS CSPRNG (getrandom/urandom). |

### Identity — DID

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| DID Core | W3C DID Core 1.0 (Decentralized Identifiers) | Vendor-neutral identity format. Lets attestations reference issuers/subjects without a central registry. |
| did:pkh | did:pkh Method Specification (ChainAgnostic) | Maps a blockchain address to a DID. Lets SIWE-authenticated wallets be referenced in W3C credentials without a custom identity scheme. |

### Identity — X.509

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| X.509 PKI | RFC 5280 (Internet X.509 PKI Certificate and CRL Profile) | The standard for TLS certificates and enterprise PKI. Required for mTLS and certificate-based service auth. |
| OCSP | RFC 6960 (X.509 Internet PKI Online Certificate Status Protocol) | Real-time revocation checking. CRLs are stale; OCSP is live. |

### Identity — JWK / COSE / JOSE

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| JWK | RFC 7517 (JSON Web Key) | Standard JSON format for representing cryptographic keys. Used by OIDC JWKS endpoints. |
| JWS | RFC 7515 (JSON Web Signature) | Standard structure for detached signatures over JSON. Used for JWTs and verifiable credential proofs. |
| COSE | RFC 8152 (CBOR Object Signing and Encryption) | Binary counterpart to JOSE for constrained environments. Used in WebAuthn and IoT attestations. |
| JOSE algorithms | RFC 7518 (JSON Web Algorithms) | The algorithm registry for JWS/JWE. Defines HS256, RS256, ES256, EdDSA, etc. |

### Merkle Trees

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| Merkle tree construction | RFC 6962 §2.1 (Certificate Transparency) | Binary hash tree with inclusion proofs. Used for batch-anchoring attestations: one on-chain root proves N off-chain attestations. |

### Verifiable Credentials

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| VC Data Model | W3C VC Data Model v2.0 (Verifiable Credentials) | Standard format for digital credentials. Lets attestations interoperate with W3C-compliant verifiers and wallets. |

### Attestations

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| Attestation canonicalization | RFC 8785 (JSON Canonicalization Scheme) | Deterministic JSON serialization so all implementations produce identical signing bytes. Without this, signature verification is non-deterministic. |
| CBOR deterministic encoding | RFC 8949 §4.2 (CBOR) | Binary alternative to JCS for constrained environments. |
| Domain separation | NIST SP 800-108 §7.2 (KDF context binding) | Binds signatures to a protocol context string so a signature from one protocol can't be replayed in another. Prevents cross-protocol signature confusion. |
| Status list revocation | W3C VC Status List v1.0 | Bitset-based revocation list. Compact, scalable way to revoke attestations without per-attestation on-chain state. |

### Security Hygiene

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| Constant-time comparison | NIST SP 800-38A Appendix D (timing attack guidance); CWE-208 | `==` on byte slices leaks length and prefix via timing. Constant-time comparison prevents side-channel key recovery. |
| JWT best practices | RFC 8725 (JSON Web Token Best Current Practices) | The authoritative BCP for JWT security — alg confusion, key rotation, audience binding. |

### Military-Grade & National Security References

These standards govern use of cryptographic primitives in US national security
systems (NSS), federal systems, and classified environments. The Godoc comments
must cite them where applicable — both when a primitive meets the requirement
and when it does not, so consumers building NSS/federal systems know what to swap.

| Capability | Standard | Applicability |
|------------|----------|---------------|
| AES-256-GCM | CNSA 2.0 (NSA Commercial National Security Algorithm Suite 2.0, 2022) | AES-256 is the CNSA 2.0 symmetric cipher for TOP SECRET. Our AES-256-GCM meets this. Cite in Godoc. |
| SHA-256 / SHA-3 | CNSA 2.0 | CNSA 2.0 requires SHA-384 for TS, not SHA-256. SHA-256 is fine for unclassified and commercial. Note the gap in Godoc. |
| Keccak-256 | Not in CNSA 2.0 | Keccak-256 is Ethereum-specific, not NSS-approved. No CNSA citation. |
| BLAKE3 | Not in CNSA 2.0 | BLAKE3 is not NSS-approved. No CNSA citation. |
| RSA (≥2048) | CNSA 2.0 | CNSA 2.0 requires RSA ≥3072 for TS. Our RSA implementation supports arbitrary key sizes; note the TS minimum in Godoc. |
| ECDSA P-256 | CNSA 2.0 | CNSA 2.0 requires P-384 for TS. P-256 is fine for unclassified/commercial. Note the gap. |
| ECDSA P-384 | CNSA 2.0 | P-384 is the CNSA 2.0 curve for TS. Cite in Godoc. |
| Ed25519 | FIPS 186-5 (approved); not in CNSA 2.0 | Ed25519 is approved in FIPS 186-5 but not yet in CNSA 2.0. Note both in Godoc. |
| secp256k1 | Not in CNSA 2.0 or FIPS 186-5 | secp256k1 is not an NIST/NSA-approved curve. It's Ethereum/Bitcoin-specific. No CNSA citation. Note the gap. |
| X25519 | RFC 7748; not in CNSA 2.0 | CNSA 2.0 requires P-384 ECDH (SP 800-56A Rev3) for TS. X25519 is fine for commercial. Note the gap. |
| HKDF-SHA256 | SP 800-56C Rev2 (KDF for key agreement) | HKDF is NIST-approved as a KDF. Cite SP 800-56C. |
| Envelope encryption (KEK/DEK) | CSfC (NSA Commercial Solutions for Classified) | Layered crypto is a CSfC pattern — two independent layers of commercial crypto for classified data. Our envelope encryption implements this pattern. Cite CSfC. |
| CSPRNG | SP 800-90A (DRBG); FIPS 140-3 §4.9.2 | The RNG must be a NIST-approved DRBG in FIPS mode. Go's `crypto/rand` uses the OS RNG, which is FIPS-validated on certified platforms. Cite both. |
| FIPS 140-3 validation | FIPS 140-3 (Cryptographic Module Validation) | Go stdlib is not FIPS-validated by default. FIPS mode requires `GOEXPERIMENT=boringcrypto` or a certified Go build. Note this in package-level Godoc for `crypto/aead` and `crypto/hash`. |
| Cryptographic protection | SP 800-53 Rev5 SC-13 | Federal control requiring FIPS-validated crypto for information protection. Cite when a function is the primary crypto boundary. |
| Key management | SP 800-57 Rev5 (Recommendation for Key Management) | NIST key management guidance — key lifetimes, rotation, storage. Cite on key-generation functions. |

## Linked Plan

- Plan: `plans/PLAN-001.md` (created by Architect)
- Tasks: listed in the plan under Workstreams

## Source Material

- `trakt2/trakt2-api/internal/infra/security/keys.go` — Ed25519 RootKey, Attestation
  signing, HKDF DeriveChildKey (primary consolidation target)
- `trakt2/trakt2-api/internal/infra/security/oauth.go` — RandomTokenGenerator (the raw
  random byte generation part; token formatting moves to `auth`)
- `ghost-protocol/backend/internal/security/jwt.go` — HS256 TokenIssuer (the HMAC-SHA256
  signing primitive is a `trust` concern; JWT structure is `auth`)
- `Go Trust & Security Platform — Architecture Specification.md` (root)
- `spec/00-thesis.md` (root)
- build-web3 skill — EVM/Keccak-256/EIP-712 guidance for the secp256k1 and hash primitives
