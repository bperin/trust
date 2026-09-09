# trust — cryptographic trust toolkit

## Problem

Every project re-implements the same primitives: key generation, signing,
verification, hashing, session management, OAuth flows. The code is either
hand-rolled per repo (trakt2, smart-job-search, ghost-protocol) or pulled
from scattered libraries with different conventions and dependency profiles.

Meanwhile, Web3 and AI agent projects need a shared notion of identity,
proof, and attestation that spans cryptographic primitives, user auth,
and blockchain anchoring — none of which existing Go libraries tie
together cleanly.

## Thesis

Three Go modules with clean dependency boundaries:

```
auth ──────┐
            ▼
          trust
            ▲
            │
          chain
```

| Module | Question | Depends on |
|--------|----------|------------|
| auth | Who are you? | trust |
| trust | Can you cryptographically prove it? | (nothing) |
| chain | Can that proof be anchored to a blockchain? | trust |

Applications compose what they need:

- Normal SaaS app: `auth + trust`
- Attestation registry: `trust + chain`
- User-facing Web3/agent app: `auth + trust + chain`

## Module boundaries

### trust — cryptographic core

No application auth. No blockchain RPC. No QuickNode. Maximally portable.

```
trust/
├── crypto/
│   ├── hash/          # SHA-256, SHA-3, BLAKE3 wrappers
│   ├── aead/          # AES-GCM, ChaCha20-Poly1305
│   ├── hkdf/          # HKDF-SHA256 key derivation
│   ├── ed25519/       # Ed25519 sign/verify, key generation
│   ├── secp256k1/     # secp256k1 sign/verify (EVM keys)
│   └── x25519/        # X25519 ECDH key exchange
├── identity/
│   ├── did/           # W3C DID parsing and resolution
│   ├── didpkh/        # did:pkh (blockchain account DIDs)
│   └── x509/          # X.509 certificate parsing
├── merkle/            # Merkle tree construction, proofs, verification
├── signature/         # Multi-sig, threshold sig, signature aggregation
├── credential/        # W3C Verifiable Credentials data model
└── attestation/       # Higher-level attestation protocol on top of credentials
```

### auth — user/service authentication

```
auth/
├── oidc/              # OpenID Connect client
├── oauth/             # OAuth2 flows (GitHub, Google, custom)
├── webauthn/          # Passkey registration and login
├── session/           # Server-side session store, cookie management
└── claims/            # JWT/OIDC claim parsing and validation
```

Maps authenticated users → `trust.Identity`. Handles:

- OIDC provider discovery and token validation
- OAuth2 authorization code flow
- WebAuthn/passkey registration and login
- Session token issuance, validation, revocation
- Claim extraction (JWT, OIDC userinfo)

### chain — blockchain integration

```
chain/
├── evm/               # EVM transaction building and signing
├── ethereum/          # Ethereum-specific types and constants
├── wallet/            # Key management, signing, address derivation
├── eip712/            # EIP-712 typed structured data signing
├── rpc/               # JSON-RPC client abstraction
└── quicknode/         # QuickNode provider adapter (HyperCore streams, etc.)
```

Handles:

- EVM transaction construction and signing
- secp256k1 key → Ethereum address derivation
- EIP-712 typed data hashing and signing
- Merkle-root anchoring (on-chain attestation)
- RPC provider abstraction (QuickNode, Alchemy, public)
- Contract ABI encoding/decoding

## Design principles

1. **trust has zero dependencies on auth or chain.** It is pure crypto.
2. **auth depends on trust** for identity types and signature verification.
3. **chain depends on trust** for crypto primitives and Merkle proofs.
4. **No DI frameworks.** Explicit constructor composition.
5. **No reflection.** Type-safe APIs.
6. **Stdlib-first.** Third-party only when it saves significant work.
7. **Each module is independently versionable.** go.work ties them together
   for local development; `go get` for consumers.
8. **QuickNode is an adapter inside chain, not its own module.** Same for
   any future provider (Alchemy, Infura, etc.).
