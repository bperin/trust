# trust

A reusable Go platform for authentication and cryptography. Three modules, one
dependency direction, no duplicated crypto.

```
auth ──────┐
            ▼
          trust
            ▲
            │
          chain
```

- **trust** — cryptographic primitives, identity, attestations, proofs. No HTTP,
  no database, no application logic. Just crypto.
- **auth** — OIDC, OAuth2, WebAuthn, SIWE, JWT, sessions. Depends on trust for
  all crypto. Never re-implements a hash or signature.
- **chain** — EVM transactions, EIP-712, Merkle anchoring, RPC. Depends on trust
  for crypto. QuickNode is an adapter, not a foundation.

## Why this exists

Two projects ([ghost-protocol](https://github.com/bperin/ghost-protocol) and
trakt2) were reimplementing the same JWT, OAuth, and attestation code. Same
HS256 token issuer, same bcrypt verifier, same Ed25519 attestation signing.
This platform consolidates that into one place so neither project — or any
future project — has to roll its own crypto again.

## What's here right now

Specs, an algorithm registry, and skill wiring. No implementation code yet.

The specs define what to build. The registry defines what each algorithm is,
where it comes from, how hard it is to break, and whether the NSA approves it
for TOP SECRET systems. The skills provide definitive source knowledge so the
implementation doesn't guess at crypto.

### Specs

| Spec | Module | What it covers |
|------|--------|----------------|
| [SPEC-001](.ai-trust/context/specs/SPEC-001.md) | trust | SHA-256, SHA-3, Keccak-256, BLAKE3, HKDF, AES-256-GCM, XChaCha20-Poly1305, envelope encryption, Ed25519, secp256k1, RSA, ECDSA, X25519, DID, X.509, JWK/COSE/JOSE, Merkle trees, verifiable credentials, attestations |
| [SPEC-002](.ai-trust/context/specs/SPEC-002.md) | auth | JWT (HS256/RS256/ES256/EdDSA), OAuth2 + PKCE + state, OIDC discovery, WebAuthn/passkeys, SIWE/EIP-4361, sessions, refresh-token rotation, bcrypt |
| [SPEC-003](.ai-trust/context/specs/SPEC-003.md) | chain | EVM transactions (legacy/1559/2930), EIP-712 typed data, RLP, wallet abstraction, Merkle root anchoring, RPC abstraction, QuickNode adapter |

### Algorithm registry

[`trust/algorithms.json`](trust/algorithms.json) catalogues every algorithm
with:

- **The math** — Merkle-Damgård vs sponge vs ARX vs Montgomery ladder, not just
  the name
- **Origin** — who designed it, when, and what it replaced
- **Breakability** — can you actually break it? what happens when it fails?
  (nonce reuse on secp256k1 leaked the PS3 private key in 2010; AES-GCM nonce
  reuse leaks the GHASH key and plaintext)
- **CNSA 2.0** — whether the NSA approves it for TOP SECRET systems, and if not,
  what to swap to
- **Skill mapping** — which skill provides definitive implementation knowledge

[`trust/ALGORITHMS.md`](trust/ALGORITHMS.md) is the human-readable version with
summary tables and quick-reference guides.

### Skill-gated implementation

No algorithm is implemented unless a skill with definitive source knowledge is
loaded first. Three skills are always on:

- `go-systems-programmer` — Go structure, explicit wiring, stdlib-first
- `go-security-expert` — crypto/rand, constant-time, alg enforcement, claim validation
- `go-memory-oom-guard` — key material lifetime, OOM prevention

Nine project-local skills load on demand based on what the current workstream
touches. The standout is [Wycheproof](https://github.com/google/wycheproof)
(via [Trail of Bits](https://www.trailofbits.com/)) — known-attack test vectors
that catch bugs standards-compliant test vectors miss.

See [AGENTS.md](AGENTS.md) for the full skill-gated implementation rules,
testing rules, and Godoc rules.

## Godoc rules

Every exported declaration cites its governing standard inline:

```go
// Encrypt implements [SP 800-38D] §7.1 (AES-256-GCM) — authenticated encryption
// with a 96-bit random nonce prefixed to ciphertext.
// Meets [CNSA 2.0] AES-256 requirement for TOP SECRET systems.
func (e *AESGCM) Encrypt(plaintext, aad []byte) ([]byte, error)
```

When a primitive doesn't meet a national security standard, the Godoc says so:

```go
// SharedSecret implements [RFC 7748] §6.1 (X25519 ECDH) — derives a 32-byte
// shared secret from a private key and peer public key.
// NOTE: X25519 is not in [CNSA 2.0]; national security systems require
// P-384 ECDH per [SP 800-56A Rev3].
```

## Testing

Known vectors for every crypto primitive. Negative tests for every failure
mode. Race detector. `govulncheck`. No skipped tests. If Wycheproof has vectors
for the algorithm, those tests are required too.

## Status

Specs and registry are done. Implementation is next. The first plan will
target the trust module's crypto primitives, starting with hashing and working
up through signing, AEAD, and attestations.

## License

[MIT](LICENSE)
