# trust — Algorithm Registry

> Every cryptographic algorithm implemented in the `trust` module is catalogued
> in [`algorithms.json`](./algorithms.json) with its mathematical basis, origin,
> security strength, breakability status, platform usage, and national-security
> applicability. This README is the human-readable summary. The JSON file is the
> machine-readable source of truth.

## Why this exists

When you read a Godoc comment that says `// Encrypt implements [SP 800-38D]`, you
know the standard. But you don't know:

- **What the math is** — is this Merkle-Damgård? Sponge? ARX? Edwards curve?
- **Where it came from** — who designed it, when, and why
- **How hard it is to break** — is it like MD5 (trivially broken) or like SHA-256
  (no practical attacks in 20+ years)?
- **What happens when it fails** — does nonce reuse leak the key? Does a
  collision break the whole system?
- **Whether the NSA approves it** — can you use this in a TS system or not?

The registry answers all of these in a standardized format.

## JSON Schema

Every algorithm entry in `algorithms.json` follows this structure:

```
Algorithm
├── id                    # slug identifier ("sha-256", "aes-256-gcm")
├── name                  # human-readable name
├── category              # hash | kdf | aead | envelope | key_agreement | signature | random
├── standard
│   ├── id                # citation string used in Godoc ("[FIPS 180-4]")
│   ├── title             # full standard title
│   ├── publisher         # NIST | IETF | W3C | SEC | Ethereum | ...
│   └── url               # link to the actual document
├── origin
│   ├── designed_by       # person or org
│   ├── year              # when
│   └── context           # the story — why it exists, what it replaced
├── math
│   ├── construction      # high-level structure (Merkle-Damgård, sponge, Feistel, ...)
│   ├── primitive         # the core operation
│   ├── key_bits           # key size (for signing/encryption)
│   ├── output_bits        # output size (for hashes)
│   ├── nonce_bits         # nonce size (for AEAD)
│   ├── tag_bits           # auth tag size (for AEAD)
│   ├── rounds             # round count
│   └── operations         # what arithmetic is used (ARX, GF(2^128), mod exp, ...)
├── security
│   ├── bits_of_security   # equivalent symmetric strength
│   ├── status             # secure | secure_with_caveats | broken | weakened
│   ├── collision_resistance_bits  # for hashes
│   ├── preimage_resistance_bits   # for hashes
│   ├── known_attacks      # list of attack names/descriptions
│   └── breakability       # plain-language: can you break it? how? what happens?
├── usage_in_platform      # list of where this is used in trust/auth/chain
├── dependencies
│   ├── source             # Go stdlib | golang.org/x/crypto | third-party
│   ├── package            # import path
│   └── third_party        # bool
├── national_security
│   ├── cnsa_2_0           # approved_for_ts | not_approved_for_ts | not_listed
│   ├── cnsa_note          # what CNSA 2.0 says about this
│   ├── fips_140_3         # validated_in_approved_module | not_validated
│   └── sp_800_57          # approved | not_approved_for_nss
├── skill                  # which project-local skill provides definitive knowledge
│   ├── primary            # skill name (in ~/.agents/skills/)
│   └── secondary          # list of supporting skill names
└── godoc_citation         # the exact string to use in Godoc comments
```

## Algorithm Summary

### Hash

| Algorithm | Standard | Security | Status | CNSA 2.0 | Source |
|-----------|----------|----------|--------|----------|--------|
| SHA-256 | FIPS 180-4 | 128-bit | secure | not for TS (needs SHA-384) | stdlib |
| SHA-3 | FIPS 202 | 128-bit | secure | not listed | x/crypto |
| Keccak-256 | EIP-191 | 128-bit | secure | not listed (Ethereum-specific) | x/crypto |
| BLAKE3 | BLAKE3 Spec | 128-bit | secure | not listed | third-party |

### Key Derivation

| Algorithm | Standard | Security | Status | CNSA 2.0 | Source |
|-----------|----------|----------|--------|----------|--------|
| HKDF-SHA256 | RFC 5869 | 256-bit | secure | approved (SP 800-56C) | x/crypto |

### AEAD

| Algorithm | Standard | Security | Status | CNSA 2.0 | Source |
|-----------|----------|----------|--------|----------|--------|
| AES-256-GCM | SP 800-38D | 256-bit | secure (nonce-reuse catastrophic) | approved for TS | stdlib |
| XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha | 256-bit | secure | not listed | x/crypto |

### Envelope

| Algorithm | Standard | Security | Status | CNSA 2.0 | Source |
|-----------|----------|----------|--------|----------|--------|
| AES-KW | RFC 3394 | 256-bit | secure | approved for TS | x/crypto |
| HPKE | RFC 9180 | 128-bit | secure | not listed | x/crypto |

### Key Agreement

| Algorithm | Standard | Security | Status | CNSA 2.0 | Source |
|-----------|----------|----------|--------|----------|--------|
| X25519 | RFC 7748 | 128-bit | secure | not for TS (needs P-384) | x/crypto |

### Signatures

| Algorithm | Standard | Security | Status | CNSA 2.0 | Source |
|-----------|----------|----------|--------|----------|--------|
| Ed25519 | RFC 8037 / FIPS 186-5 | 128-bit | secure | not listed (FIPS-approved) | stdlib |
| secp256k1 | SEC 2 v2 | 128-bit | secure with caveats (nonce-reuse) | not listed (not NIST) | third-party |
| RSA-PSS | RFC 8017 | 112-bit (2048) / 128-bit (3072) | secure | approved for TS (>=3072) | stdlib |
| ECDSA P-256 | FIPS 186-4 | 128-bit | secure with caveats (nonce-reuse) | not for TS (needs P-384) | stdlib |
| ECDSA P-384 | FIPS 186-4 | 192-bit | secure with caveats (nonce-reuse) | approved for TS | stdlib |

### Random

| Algorithm | Standard | Security | Status | CNSA 2.0 | Source |
|-----------|----------|----------|--------|----------|--------|
| CSPRNG | SP 800-90A | 256-bit | secure | approved for TS | stdlib |

## Breakability Notes

The `breakability` field in each JSON entry is the plain-language answer to "can
someone actually break this?" Here's the quick reference:

| Algorithm | Can you break it? | What happens if you do? |
|-----------|-------------------|------------------------|
| SHA-256 | No. Birthday bound at 2^128 is expected, not a weakness. | A collision would let you forge two documents with the same hash. Not feasible. |
| Keccak-256 | No. Same as SHA-3, different padding. | Same as SHA-256. |
| BLAKE3 | No. Inherits BLAKE2s analysis. | Same as SHA-256. |
| AES-256-GCM | No (on the cipher). **Yes if nonce reused.** | Nonce reuse leaks the GHASH key and allows plaintext recovery + forgery. The library manages nonces to prevent this. |
| XChaCha20-Poly1305 | No. 192-bit nonce makes random-nonce collision impossible. | N/A — nonce reuse is not a practical concern with 192-bit random nonces. |
| Ed25519 | No. Deterministic signing eliminates nonce failures. | N/A. |
| secp256k1 | No (on the curve). **Yes if nonce reused.** | Nonce reuse leaks the private key completely. This is how the PlayStation 3 was hacked in 2010. RFC 6979 deterministic nonces prevent it. We enforce them. |
| RSA-PSS | No (classically). **Yes with a quantum computer (Shor's).** | Shor's algorithm factors n in polynomial time. Not yet practical (needs millions of qubits). NIST PQC (CRYSTALS-Dilithium) is the post-quantum replacement. |
| ECDSA P-256/P-384 | No (on the curve). **Yes if nonce reused.** Same quantum concern as RSA. | Same as secp256k1 for nonce reuse. Shor's algorithm breaks ECDLP. |
| X25519 | No. | N/A. Quantum: Shor's breaks ECDH. |

## National Security Quick Reference

| If you're building... | Use these | Don't use these |
|----------------------|-----------|-----------------|
| Commercial product | Anything in this registry | N/A — all are commercially safe |
| Federal / FISMA system | SHA-256, AES-256-GCM, RSA-2048+, ECDSA P-256, Ed25519 (FIPS 186-5) | secp256k1, Keccak-256, BLAKE3, X25519 (not FIPS-validated in most modules) |
| TOP SECRET (CNSA 2.0) | AES-256-GCM, SHA-384 (not SHA-256), RSA-3072+, ECDSA P-384 | secp256k1, X25519, Ed25519, BLAKE3, Keccak-256, XChaCha20-Poly1305 |
| Post-quantum (future) | CRYSTALS-Dilithium (signing), CRYSTALS-Kyber (KEM) — not yet implemented | RSA, ECDSA, ECDH (all broken by Shor's) |

## Skill Mapping

Every algorithm is associated with a project-local skill (in `~/.agents/skills/`)
that provides definitive source knowledge. No algorithm is implemented unless
its skill is loaded first. This is enforced by the Skill-Gated Implementation
rule in `AGENTS.md`.

| Skill | Source | Installs | Algorithms covered |
|-------|--------|----------|--------------------|
| `wycheproof` | trailofbits/skills | 4.4K | aes-256-gcm, xchacha20-poly1305, x25519, ed25519, secp256k1, rsa-pss, ecdsa-p256, ecdsa-p384 — known attack test vectors |
| `golang-security` | samber/cc-skills-golang | 38.9K | All — crypto/rand, constant-time, secrets management, injection prevention |
| `golang-testing` | samber/cc-skills-golang | 39.7K | All — table-driven tests, fuzzing, fixtures, goroutine leak detection |
| `golang-code-style` | samber/cc-skills-golang | 40.4K | All — Go style conventions, line length, control flow |
| `golang-error-handling` | samber/cc-skills-golang | 39.7K | All — error wrapping, sentinel errors, slog integration |
| `golang-concurrency` | samber/cc-skills-golang | 38.4K | Nonce stores, session caches, key registries |
| `golang-performance` | samber/cc-skills-golang | 38.9K | sha-256, sha-3, keccak-256, blake3, aes-256-gcm, merkle — allocation, pooling, hot-path |
| `implementing-digital-signatures-with-ed25519` | mukul975/anthropic-cybersecurity-skills | 63 | ed25519 — key generation, signing, verification, tradeoffs |
| `ethereum` | mindrally/skills | 687 | keccak-256, secp256k1 — Ethereum context, EIP standards |

**Trail of Bits Wycheproof** is the standout. It encodes known attacks and edge
cases as test vectors for AES, RSA, ECDSA, ECDH, Ed25519, and more. Every
crypto primitive that has Wycheproof vectors must be tested against them —
not just against the standard's own test vectors. Wycheproof catches bugs that
standards-compliant test vectors miss (e.g., invalid curve points, biased
nonces, modular arithmetic edge cases).

## Adding a New Algorithm

1. Add the entry to `algorithms.json` with all fields populated, including the
   `skill` field mapping to a project-local skill.
2. If no existing skill covers this algorithm, search for one with
   `npx skills find "<algorithm name>"` and install it with
   `npx skills add <owner/repo@skill> -y`. Verify it has 1K+ installs or comes
   from a reputable source (Trail of Bits, NIST, OWASP, samber, etc.).
3. Add the standard citation to the "Standards & References" section in the
   relevant SPEC.
4. Add the military-grade reference if applicable.
5. Implement the algorithm with Godoc comments citing the `godoc_citation` field.
6. Add a test vector from the standard's test suite.
7. If Wycheproof has vectors for this algorithm, add Wycheproof tests too.
8. Update this README's summary tables.
