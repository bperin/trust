# Go Trust & Security Platform — Architecture Specification

## Objective

Build a reusable, blockchain-interoperable security platform for Go applications. The platform must support ordinary user authentication, cryptographic identity, signed attestations/credentials, Merkle proofs, and blockchain anchoring without coupling the core security primitives to any specific application, blockchain, RPC provider, or authentication provider.

The system should be implemented as **three Go modules** with strict dependency boundaries:

```text
auth  ────────┐
              ▼
            trust
              ▲
              │
chain ────────┘
```

`trust` is the foundational module. `auth` and `chain` may depend on `trust`; `trust` must never depend on either.

---

## Module 1: `trust` — Cryptographic Trust Core

Purpose: provide portable cryptographic primitives and interoperable identity/proof formats.

Required capabilities:

- SHA-256 and SHA-3 hashing
- HMAC and HKDF
- AES-256-GCM and ChaCha20-Poly1305
- secure random generation
- Ed25519 signatures
- ECDSA / secp256k1 support
- X25519 key agreement
- JWK / COSE / JOSE interoperability where appropriate
- X.509 certificate parsing and verification
- DID representation and resolution interfaces
- `did:pkh` representation
- Merkle tree construction and inclusion proofs
- EIP-712 typed-data representation/signing interfaces
- W3C Verifiable Credential / credential primitives
- generic signed attestation objects

The core abstraction should be algorithm-independent wherever practical. Applications should operate on interfaces such as `Signer`, `Verifier`, `Hasher`, `Identity`, `Credential`, `Attestation`, and `MerkleProof` rather than directly depending on implementation details.

The module must favor established standards over proprietary formats.

---

## Module 2: `auth` — Authentication & Authorization

Purpose: answer **"Who is this user/service, and what are they authorized to do?"**

Support:

- OAuth 2.x
- OpenID Connect
- JWT validation
- WebAuthn / FIDO2 / passkeys
- session management
- service/workload authentication
- mTLS where appropriate
- claims extraction and validation
- issuer/audience/nonce/state validation
- mapping authenticated identities into `trust.Identity`

Authentication must remain separate from cryptographic attestation. Successfully authenticating through OIDC does not itself constitute proof of ownership of a blockchain address or authority to issue an attestation.

The package should make it possible to establish a relationship such as:

```text
OIDC subject
     ↓
authenticated identity
     ↓
cryptographic identity / DID
     ↓
authorized signer
```

Do not implement an application-specific user database inside this module.

---

## Module 3: `chain` — Blockchain Interoperability

Purpose: connect the trust system to blockchains without contaminating the core with provider-specific dependencies.

Initial target: EVM-compatible chains.

Support:

- Ethereum/EVM addresses
- secp256k1 signing
- EIP-712
- transaction construction/signing interfaces
- contract interaction
- event/log verification
- Merkle-root anchoring
- attestation anchoring
- chain ID/network identification
- wallet/key abstractions
- RPC provider interfaces

QuickNode must be implemented as an **RPC/provider adapter**, not as a foundational dependency.

The architecture must permit:

```text
trust.Attestation
      ↓
content hash / Merkle root
      ↓
chain.Anchor(...)
      ↓
EVM contract
```

The same attestation must remain independently verifiable without requiring QuickNode.

---

## Attestation Model

Attestations are a first-class object and must be designed for interoperability.

Conceptually:

```text
Attestation
├── issuer identity
├── subject identity
├── timestamp
├── payload/content hash
├── claims
├── signature
├── credential metadata
└── optional blockchain anchor
```

An attestation should prove that a particular issuer signed a particular statement about a particular subject/content at a particular point in time.

Large data should **not** be stored directly on-chain. Hashes, Merkle roots, identifiers, or compact commitments should be anchored on-chain while the underlying content remains off-chain.

Verification must support:

```text
content
  → hash
  → attestation
  → signature verification
  → optional Merkle proof
  → optional blockchain anchor verification
```

---

## Agent Interoperability

The architecture must be suitable for emerging trusted-agent systems rather than assuming agents are ordinary OAuth clients.

Agents should be capable of possessing cryptographic identities and signing consequential actions. The platform should provide primitives usable by agent protocols such as A2A and related agent authentication/authorization systems.

Do not hard-code the core around a single agent protocol. Agent integrations belong above `trust`.

The design should allow:

```text
Human/User
    ↓
OIDC / WebAuthn
    ↓
Identity
    ↓
Agent
    ↓
Cryptographic signer
    ↓
Signed action / credential / attestation
    ↓
optional blockchain anchor
```

The system must distinguish:

1. authentication of the human,
2. identity of the agent,
3. authorization granted to the agent,
4. cryptographic signing of an action,
5. independent verification of the resulting proof.

---

## Security Requirements

Use modern, well-reviewed primitives and standard libraries where possible. Never invent cryptographic algorithms or serialization formats.

Private keys must never be logged, serialized accidentally, or exposed through generic debugging/error mechanisms.

Separate key-encryption keys from data-encryption keys where envelope encryption is required.

All cryptographic APIs must have explicit error handling and verification failures must fail closed.

Every serialized security object should have a version/type identifier to permit future protocol evolution.

All externally supplied signatures, certificates, credentials, JWTs, Merkle proofs, and blockchain data must be treated as untrusted input and validated before use.

---

## Deliverable

Produce the three Go modules with:

1. clean package boundaries,
2. idiomatic Go APIs,
3. interoperability tests,
4. test vectors for cryptographic operations,
5. serialization/deserialization tests,
6. signature verification tests,
7. Merkle inclusion-proof tests,
8. EVM/EIP-712 interoperability tests,
9. X.509/JWK/COSE/JOSE interoperability tests where supported,
10. documentation showing how an application can use only `auth`, only `trust`, or all three.

Do **not** over-engineer the first implementation. Establish the cryptographic and identity pipeline first, then add provider-specific integrations as adapters.

The primary design principle is:

> **Authenticate users. Identify agents. Sign claims. Prove integrity. Anchor proofs when useful. Never make any individual provider or blockchain a requirement for verification.**