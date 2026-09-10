# trust

> **Zero-Dependency Cryptographic Trust, Identity, & Chain Suite for Agentic Commerce**
> *Created & Architected by Brian Perin — San Francisco, CA*

---

## The Vision: Cryptographic Primitives for Agentic Commerce

As AI agents act as autonomous economic actors executing transactions, signing verifications, and bridging Web2 authentication with Web3 settlement, they cannot rely on fragile, scattered, or framework-coupled crypto libraries. 

**trust**, **auth**, and **chain** form the foundational cryptographic toolkit designed specifically for **agentic commerce**:
- **Autonomous Agent Identity**: DIDs (`did:pkh`), W3C Verifiable Credentials, and cryptographic capabilities.
- **Cross-Layer Bridging**: Seamless translation between Ed25519 (AI agent keys), secp256k1 (EVM settlement), RSA/ECDSA (enterprise SaaS integrations), and JWK/COSE/JWT encoders.
- **Zero-Dependency Core**: The `trust` core has zero external non-stdlib dependencies (except vetted cryptographic primitives), ensuring absolute portability across sandboxed agent runtimes.

```
auth ──────┐
            ▼
          trust
            ▲
            │
          chain
```

---

## 10 Core Code Examples (Divided by Operational Tier)

### Tier 1: Cryptographic Core (`trust/crypto/*`)

#### 1. AES-256-GCM Authenticated Encryption
```go
key := rand.Bytes(32) // 256-bit key
ciphertext, err := aead.Encrypt([]byte("secret agent data"), key, []byte("aad-context"))
plaintext, err := aead.Decrypt(ciphertext, key, []byte("aad-context"))
```

#### 2. XChaCha20-Poly1305 Encryption
```go
key := rand.Bytes(32)
ciphertext, err := aead.EncryptXChaCha20([]byte("payload"), key, nil)
plaintext, err := aead.DecryptXChaCha20(ciphertext, key, nil)
```

#### 3. Deterministic Ed25519 Signing
```go
priv, pub, err := ed25519.GenerateKey()
sig, err := priv.Sign([]byte("agent message"))
valid := pub.Verify(sig, []byte("agent message"))
```

#### 4. secp256k1 EVM Signing & Recovery
```go
priv, pub, err := secp256k1.GenerateKey()
hash := sha256.Sum256([]byte("evm transaction payload"))
sig, err := priv.Sign(hash[:])
recoveredPub, err := secp256k1.Recover(hash[:], sig)
```

#### 5. RSA-PSS & PKCS#1 v1.5 Signing
```go
priv, pub, err := rsa.GenerateKey(2048)
sig, err := priv.SignPSS([]byte("enterprise payload"), crypto.SHA256)
valid := pub.VerifyPSS(sig, []byte("enterprise payload"), crypto.SHA256)
```

#### 6. Envelope Encryption / AES-KW
```go
kek := rand.Bytes(32) // Key Encryption Key
wrapped, err := envelope.WrapKey(dek, kek)
unwrapped, err := envelope.UnwrapKey(wrapped, kek)
```

---

### Tier 2: Authentication & Identity (`auth/*`)

#### 7. Stateless JWT Claims with Custom Roles
```go
c := claims.Claims{
    Subject:   "agent-007",
    Issuer:    "https://agent.network",
    ExpiresAt: time.Now().Add(time.Hour).Unix(),
    Extra: map[string]any{"role": "autonomous-treasury-bot"},
}
token, err := claims.Sign(c, privKey, claims.Options{Algorithm: "EdDSA"})
verified, err := claims.Verify(token, pubKey, claims.Options{Algorithm: "EdDSA"})
role := verified.Extra["role"]
```

#### 8. Cryptographically Secure Sessions
```go
store := session.NewMemoryStore(time.Hour)
sess, token, err := store.Create(ctx, "agent-007", map[string]any{"tier": "pro"})
fetched, err := store.Get(ctx, token)
```

---

### Tier 3: Chain & Proofs (`chain/*`, `trust/merkle`)

#### 9. Ethereum Address Derivation & EIP-55 Checksums
```go
priv, pub, err := secp256k1.GenerateKey()
addr, err := ethereum.FromPublicKey(pub)
eip55Hex := addr.Hex() // e.g., 0x52908400098527886E0F7030069857D2E4169EE7
```

#### 10. Binary Merkle Tree Inclusion Proofs
```go
tree, err := merkle.New([][]byte{[]byte("leaf1"), []byte("leaf2")})
root := tree.Root()
proof, err := tree.Proof(0)
valid := proof.Verify(root, []byte("leaf1"), 0, tree.Size())
```

---

## Roadmap: Post-Quantum Cryptography & Agent Discovery

- **Post-Quantum Cryptography (PQC)**:
  - Integration of **ML-KEM (Kyber)** for key encapsulation (CNSA 2.0 compliant quantum-safe transport).
  - Integration of **ML-DSA (Dilithium)** for quantum-resistant agent signatures.
- **ERC-8004 / Decentralized Agent Discovery**:
  - Integration of smart contract registry standards for verifiable agent identity lookup and capability advertisement on-chain.

---

## Provenance & Cryptographic Attestation

To establish immutable proof of authorship and repository integrity, the exact commit hash and repository state are cryptographically attested below by the creator.

- **Author**: Brian Perin (San Francisco, CA)
- **GitHub**: [github.com/bperin](https://github.com/bperin)
- **Repository**: [github.com/bperin/trust](https://github.com/bperin/trust)
- **Target Git Commit Hash**: `a1cc1c09cebf96cf4af5861946964f29067c05ae`
- **Attestation Statement**: 
  > *"I, Brian Perin, certify that I am the original architect and creator of the trust platform, auth module, and chain module suites for agentic commerce. This attestation binds my identity to commit `a1cc1c09cebf96cf4af5861946964f29067c05ae`."*

## License

[MIT](LICENSE) © 2026 Brian Perin
