# trust

[![Go Reference](https://pkg.go.dev/badge/github.com/bperin/trust.svg)](https://pkg.go.dev/github.com/bperin/trust)
[![GitHub Release](https://img.shields.io/github/v/release/bperin/trust?sort=semver)](https://github.com/bperin/trust/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/bperin/trust)](https://goreportcard.com/report/github.com/bperin/trust)
[![CI](https://github.com/bperin/trust/actions/workflows/ci.yml/badge.svg)](https://github.com/bperin/trust/actions/workflows/ci.yml)
[![Build](https://img.shields.io/badge/build-0-2ea44f)](https://github.com/bperin/trust/actions/workflows/build-number.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The product boundary for the `trust`, `auth`, and `chain` modules is defined in
[`PRODUCT.md`](PRODUCT.md).

> **Go primitives and protocol adapters for cryptographic identity, authorization, delegation, attestations, proofs, and blockchain commitments.**
> _Created & Architected by Brian Perin — San Francisco, CA_

<!-- build:start -->

## Build

Current build: **0** (2026-09-14). The build number increments automatically
on every push to `main` — see
[`.github/workflows/build-number.yml`](.github/workflows/build-number.yml).

<!-- build:end -->

## Modules

| Package       | Import path                            | Purpose                                                     |
| ------------- | -------------------------------------- | ----------------------------------------------------------- |
| `crypto`      | `github.com/bperin/trust/crypto/...`   | Hashes, signatures, AEAD, key exchange, envelope encryption |
| `identity`    | `github.com/bperin/trust/identity/...` | DID, JWK, X.509, did:pkh                                    |
| `merkle`      | `github.com/bperin/trust/merkle`       | Merkle tree construction and inclusion proofs               |
| `signature`   | `github.com/bperin/trust/signature`    | Algorithm dispatch, sign/verify registry                    |
| `attestation` | `github.com/bperin/trust/attestation`  | EAT/CBOR attestations with canonicalization                 |
| `auth`        | `github.com/bperin/trust/auth/...`     | OIDC, OAuth2, JWT claims, sessions                          |
| `chain`       | `github.com/bperin/trust/chain/...`    | EVM, Ethereum, wallet, EIP-712, RPC                         |
| `kms`         | `github.com/bperin/trust/kms/...`      | Remote-KMS signing core for secp256k1                       |

```bash
go get github.com/bperin/trust@latest
```

```
auth   chain   kms
  │      │      │
  └──────┼──────┘
         ▼
       trust
```

`trust` is the crypto core with zero deps on the others. `auth`, `chain`, and `kms` depend on `trust` and never on each other.

---

## Composition Model

The library's real asset is a composition model — a layered pipeline
that wires existing cryptographic standards together with a custom
delegation, attestation, and proof layer. Each stage consumes the
output of the one before it:

```
Identity → Authority → Delegation → Claim → Attestation → Proof → Commitment → Chain
```

- **Identity** — cryptographic keys and verifiable identifiers (Ed25519,
  secp256k1, RSA, ECDSA, DIDs, JWK) anchor every actor.
- **Authority** — an identity is granted the right to act (issue, sign,
  delegate) within a scoped capability.
- **Delegation** — an authority transfers a subset of its capabilities
  to another identity, producing a delegable chain of trust.
- **Claim** — a delegated authority asserts a statement about a subject
  (a credential, a role, an ownership fact).
- **Attestation** — a claim is cryptographically signed into a verifiable
  attestation (EAT/CBOR, JWT) binding the claim to its issuer.
- **Proof** — an attestation is bound to a verifier through a proof
  (Merkle inclusion, signature recovery) that can be checked offline.
- **Commitment** — a proof is anchored to a tamper-evident commitment
  (a hash root, a published digest) that fixes the state of the world.
- **Chain** — a commitment is settled on-chain (EVM, Ethereum) so the
  result is publicly verifiable and economically final.

This pipeline is the design center. Primitives are kept thin and
standard-backed; the custom logic lives in how the stages compose.

---

## Code Examples

### Tier 1: Cryptographic Core (`trust/crypto/*`)

#### AES-256-GCM Authenticated Encryption

```go
cipher, err := aead.NewAES256GCM(key) // 32-byte key
ciphertext, err := cipher.Encrypt(plaintext, []byte("v1/aead"))
plaintext, err := cipher.Decrypt(ciphertext, []byte("v1/aead"))
```

#### XChaCha20-Poly1305 Encryption

```go
cipher, err := aead.NewXChaCha20Poly1305(key) // 32-byte key
ciphertext, err := cipher.Encrypt(plaintext, []byte("v1/xchacha"))
plaintext, err := cipher.Decrypt(ciphertext, []byte("v1/xchacha"))
```

#### Ed25519 Signing

```go
priv, pub, err := ed25519.GenerateKey()
sig := priv.Sign([]byte("agent message"))
valid := pub.Verify(sig, []byte("agent message"))
```

#### secp256k1 EVM Signing & Recovery

```go
priv, pub, err := secp256k1.GenerateKey()
sig, recID, err := priv.SignRecoverable(hash[:])
recoveredPub, err := secp256k1.RecoverPubKey(sig, hash[:], recID)
```

#### RSA-PSS Signing

```go
priv, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
sig, err := priv.Sign([]byte("enterprise payload"))
valid := pub.Verify(sig, []byte("enterprise payload"))
```

#### AES Key Wrap (RFC 3394)

```go
kek, err := envelope.GenerateKEK() // 32-byte key encryption key
wrapped, err := envelope.Wrap(kek, dek)
unwrapped, err := envelope.Unwrap(kek, wrapped)
```

---

### Tier 2: Authentication & Identity (`auth/*`)

#### JWT Claims with Custom Roles

```go
c := claims.Claims{
    Subject:   "agent-007",
    Issuer:    "https://agent.network",
    ExpiresAt: time.Now().Add(time.Hour).Unix(),
    Extra:     map[string]any{"role": "autonomous-treasury-bot"},
}
token, err := claims.Sign(c, privKey, claims.Options{Algorithm: "EdDSA"})
verified, err := claims.Verify(token, pubKey, claims.Options{Algorithm: "EdDSA"})
role := verified.Extra["role"]
```

#### Session Store Interface

```go
// Implement the Store interface with your own backend (Redis, DB, etc.).
type Store interface {
    Create(ctx context.Context, userID string, ttl time.Duration, data map[string]any) (*Session, string, error)
    Get(ctx context.Context, token string) (*Session, error)
    Refresh(ctx context.Context, token string, ttl time.Duration) (*Session, error)
    Delete(ctx context.Context, token string) error
    DeleteUserSessions(ctx context.Context, userID string) error
    Close() error
}
```

---

### Tier 3: Chain & Proofs (`chain/*`, `trust/merkle`)

#### Ethereum Address Derivation & EIP-55 Checksums

```go
priv, pub, err := secp256k1.GenerateKey()
addr, err := ethereum.FromPublicKey(pub)
eip55Hex := addr.Hex() // e.g., 0x52908400098527886E0F7030069857D2E4169EE7
```

#### Binary Merkle Tree Inclusion Proofs

```go
tree, err := merkle.New([][]byte{[]byte("leaf1"), []byte("leaf2")})
root := tree.Root()
path, err := tree.Proof(0)
valid := merkle.Verify(root, []byte("leaf1"), path)
```

---

## Dependencies

The `trust` core delegates standard wire formats to vetted Go libraries:

| Dependency                 | Purpose                             |
| -------------------------- | ----------------------------------- |
| `decred/dcrd/secp256k1/v4` | secp256k1 elliptic curve operations |
| `fxamacker/cbor/v2`        | CBOR / EAT encoding                 |
| `zeebo/blake3`             | BLAKE3 hashing                      |
| `cloudflare/circl`         | HPKE (RFC 9180)                     |
| `lestrrat-go/jwx/v3`       | JWK / JWS / JWT                     |
| `veraison/go-cose`         | COSE Sign1                          |
| `golang.org/x/crypto`      | HKDF, argon2, XChaCha20-Poly1305    |

---

## Testing

Every primitive is tested against known vectors from the governing standard
(NIST, RFC, BLAKE3 spec) and Project Wycheproof where vectors exist. The test
suite runs with `-race` and `govulncheck` in CI on every push and pull request.

```bash
# Run all tests with race detector
make test

# Run govulncheck across all modules
cd trust && go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...
```

---

## Roadmap

- **Post-Quantum Cryptography (PQC)**: ML-KEM (Kyber) for key encapsulation,
  ML-DSA (Dilithium) for quantum-resistant signatures.
- **Decentralized Agent Discovery**: Smart contract registry standards for
  verifiable agent identity lookup and capability advertisement on-chain.

---

## Provenance & Cryptographic Attestation

- **Author**: Brian Perin (San Francisco, CA)
- **GitHub**: [github.com/bperin](https://github.com/bperin)
- **Repository**: [github.com/bperin/trust](https://github.com/bperin/trust)

## License

[MIT](LICENSE) © 2026 Brian Perin
