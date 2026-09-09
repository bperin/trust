# SPEC-003: chain — Blockchain Interoperability

<!-- Template hierarchy: SPEC-NNN → plans/PLAN-NNN.md → tasks/TASK-NNN.md -->
<!-- This SPEC describes WHAT and WHY. The Architect determines HOW in plans/PLAN-003.md. -->

## Supersedes

- Supersedes: the chain portion of the original combined SPEC-001
- Reason: split per architecture guidance. The original spec split EIP-712 between `trust`
  ("representation") and `chain` ("signing"), which was architecturally wrong — EIP-712 is
  Ethereum-specific (Keccak-256 domainSeparator) and belongs entirely in `chain`. The
  original spec also left `Anchor` ownership ambiguous, risking a `trust → chain`
  dependency violation. This spec resolves both: all EIP-712 lives in `chain`, and `chain`
  consumes `trust.AnchorRef` (opaque) while providing concrete `EVMAnchor` verification.
- Superseded by: none

## What

A blockchain interoperability module that connects the `trust` attestation system to
EVM-compatible chains without contaminating the core with provider-specific dependencies.
It provides EVM transaction construction and signing, EIP-712 typed-data hashing and
signing, wallet key management, and content-hash/Merkkle-root anchoring via a pluggable
RPC provider interface. QuickNode is implemented as an adapter, never a foundational
dependency. The same attestation remains independently verifiable off-chain without any
RPC provider.

## Why

- **Anchor proofs on-chain when useful.** An attestation's content hash or Merkle root can
  be committed to an EVM contract, creating a public, timestamped proof of existence that
  survives independent of the issuer.
- **Keep the core clean.** EVM-specific logic (RLP encoding, EIP-712 domain separators,
  gas/nonce management, contract ABIs) does not belong in `trust`. `chain` wraps `trust`'s
  secp256k1 and Keccak-256 primitives to build EVM-specific operations.
- **Provider-neutral.** QuickNode, Alchemy, Infura, or a public node are all interchangeable
  through one RPC interface. No provider is a hard requirement for verification.
- **Agent and Web3 interop.** Agent-signed actions and attestations can be anchored on-chain,
  and on-chain events can be verified back to `trust` identities.

## Desired Behavior

### EVM Address & Wallet

1. An application can derive an Ethereum/EVM address from a secp256k1 public key using
   `trust`'s address-derivation primitive (not re-implemented in `chain`).
2. An application can manage secp256k1 keys for signing — key generation, loading, and
   signing — using `trust`'s secp256k1 primitives.

### EIP-712 Typed Data

3. An application can define EIP-712 typed structured data (domain separator, types,
   values), compute the EIP-712 digest using `trust`'s Keccak-256, and sign it with a
   secp256k1 key using `trust`'s signing primitive.
4. An application can verify an EIP-712 signature by recovering the public key from the
   signature and digest, deriving the address, and comparing it to the expected address.
5. All EIP-712 logic (domainSeparator, hashStruct, typedData) lives in `chain` — none of
   it leaks into `trust`.

### EVM Transactions

6. An application can construct, sign, and RLP-encode EVM transactions for any chain ID
   (legacy, EIP-1559, and EIP-2930 formats).
7. Transaction signing uses `trust`'s secp256k1 signing primitive with low-s
   canonicalization and RFC 6979 deterministic nonce (enforced by `trust`).

### Anchoring

8. An application can anchor a content hash or Merkle root to an EVM contract via a
   generic anchor interface, producing an `AnchorRef` that `trust` can store in an
   attestation.
9. An application can verify an on-chain anchor by reading the anchoring contract through
   an RPC provider and confirming the stored hash matches the attestation's content hash.
10. The anchor interface is provider-neutral: the same anchor operation works against any
    EVM node. QuickNode is one adapter, not the only option.
11. An attestation with an `AnchorRef` verifies independently off-chain (signature +
    Merkle proof) without contacting any RPC provider. The on-chain anchor is an
    additional verification layer, not a requirement.

### RPC Provider Abstraction

12. An application can interact with EVM RPC providers through a pluggable interface
    supporting eth_call, eth_sendRawTransaction, eth_getTransactionReceipt, and
    eth_getLogs.
13. QuickNode is implemented as an RPC adapter, with optional HyperCore stream support
    for real-time event ingestion. The adapter is optional — the module works with any
    standard JSON-RPC endpoint.

### Contract Interaction

14. An application can encode and decode contract ABI calls for anchor verification and
    event log parsing.

## Scope

### In Scope

- `chain` module with packages: `evm`, `ethereum`, `wallet`, `eip712`, `rpc`, `quicknode`.
- EIP-712 typed-data hashing, signing, and verification (all in `chain`).
- EVM transaction construction, signing, and RLP encoding (legacy, EIP-1559, EIP-2930).
- secp256k1 key management and signing (wrapping `trust` primitives).
- Ethereum address derivation (wrapping `trust` primitive).
- Content-hash and Merkle-root anchoring via a generic anchor interface.
- On-chain anchor verification via RPC.
- RPC provider abstraction with QuickNode adapter.
- Contract ABI encoding/decoding for anchor and event operations.
- `AnchorRef` production (the reference `trust` stores) and `AnchorRef` verification
  (reading the chain to confirm).

### Out of Scope

- Cryptographic primitives — secp256k1 sign/verify, Keccak-256, address derivation
  (SPEC-001, `trust`). `chain` wraps these, does not re-implement them.
- Attestation data model, canonicalization, or off-chain verification (SPEC-001, `trust`).
- Merkle tree construction (SPEC-001, `trust`). `chain` anchors Merkle roots produced by
  `trust`; it does not build trees.
- JWT, OAuth, OIDC, WebAuthn, SIWE, sessions, password hashing (SPEC-002, `auth`).
- Non-EVM chains (Solana, Hyperliquid) in the first implementation. The `chain` interfaces
  must not preclude future non-EVM adapters, but only EVM is built now.
- QuickNode account provisioning, endpoint management, or billing tooling. The
  `quicknode` package is an RPC/stream adapter only.
- Wallet UI, key storage backends (KMS, HSM), or key rotation policies — `chain/wallet`
  handles signing; key custody is the consuming application's responsibility.
- Frontend / dashboard code.

## Constraints

- `chain` may import `trust` only. `chain` must never import `auth`.
- EIP-712 hashing must use `trust`'s Keccak-256 — no re-implementation.
- Transaction and EIP-712 signing must use `trust`'s secp256k1 signing primitive — no
  re-implementation.
- Address derivation must use `trust`'s secp256k1 address-derivation primitive — no
  re-implementation.
- `trust/attestation` must never import `chain`. `chain` produces and verifies
  `AnchorRef` values, but `trust` only stores them as opaque references.
- No reflection-based runtime DI. Explicit constructor composition.
- No interface inflation: expose concrete structs; define interfaces near the consumer.
- Private keys must never be logged or exposed.
- All on-chain data (transaction receipts, logs, contract return values) is untrusted
  input and must be validated before use.
- QuickNode is an adapter, not a foundational dependency. The module must compile and
  pass tests without a QuickNode account or API key.
- Non-EVM extensibility: the RPC and anchor interfaces should not hard-code EVM-specific
  types in a way that prevents future Solana or Hyperliquid adapters, but only EVM is
  implemented now.
- **Godoc standard citations:** every exported declaration must cite the governing
  standard in its Godoc comment (EIP number, Ethereum Yellow Paper section, RFC). Format:
  `// SignTypedData implements [EIP-712] section 3.` followed by the plain-language
  rationale. For EVM transaction types, cite the specific EIP that defines the format.

### Dependency Matrix

| Capability | Dependency | Rationale |
|------------|------------|-----------|
| secp256k1, Keccak-256, address derivation | `trust` (SPEC-001) | All crypto primitives |
| EVM types, RLP, ABI encoding | `github.com/ethereum/go-ethereum` (or minimal subset) | EVM type system, RLP, ABI |
| QuickNode HyperCore streams | QuickNode gRPC SDK (optional) | Real-time event ingestion |
| JSON-RPC | stdlib `net/http` or `golang.org/x/net/websocket` | Standard RPC calls |

## Success Criteria

1. `go build ./...` succeeds from `chain/`.
2. `go vet ./...` is clean from `chain/`.
3. `go test ./...` passes from `chain/` with no skipped tests.
4. EIP-712 typed-data hash for a known domain+types+values triple matches the reference
   vector from the EIP-712 spec (e.g., the example in EIP-712 Section 7).
5. EIP-712 signature: sign a known typed-data digest with a known secp256k1 key, recover
   the address from the signature, and it matches the expected address. A modified
   signature or digest fails recovery.
6. A secp256k1 key derives the correct Ethereum address for a known test vector (e.g.,
   the address for private key `0x1` is
   `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf`).
7. An EVM legacy transaction for a known chain ID, nonce, gas, to, value, and data is
   RLP-encoded and matches a known raw transaction hex. The transaction signature is
   canonical (low-s).
8. An EIP-1559 transaction is constructed, signed, and RLP-encoded, and the encoded
   output can be decoded back to the original fields.
9. An anchor operation writes a content hash to a mock/local EVM anchor contract and
   produces an `AnchorRef` containing the transaction hash, block number, contract
   address, and chain ID.
10. Anchor verification reads the mock/local contract and confirms the stored hash
    matches. A wrong hash (tampered attestation) fails verification.
11. An attestation with an `AnchorRef` verifies off-chain (signature + Merkle proof)
    without any RPC call. The on-chain anchor verification is an additional step that
    succeeds when the chain is available and fails gracefully (returns false, not panic)
    when the RPC provider is unreachable.
12. The `chain` module compiles and all tests pass without a QuickNode API key or
    endpoint configured (QuickNode adapter tests use mocks or are gated behind a build
    tag that requires an explicit endpoint).
13. No `auth` import exists anywhere in `chain/` (verifiable by
    `grep -r 'github.com/brianperin/auth' chain/` returning nothing).
14. No Keccak-256 or secp256k1 re-implementation in `chain/` — all crypto goes through
    `trust` (verifiable by grep: no `sha3.NewLegacyKeccak256` or
    `dcrec/secp256k1` direct imports in `chain/` outside of wrapper calls to `trust`).

## Standards & References

### EVM Fundamentals

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| EVM specification | Ethereum Yellow Paper (formal specification of the EVM) | The canonical definition of Ethereum: state transitions, gas, opcodes, transaction format. Everything else builds on this. |
| RLP encoding | Ethereum Yellow Paper Appendix B (RLP) | Recursive Length Prefix — the serialization format for EVM transactions and blocks. Every signed transaction is RLP-encoded. |
| Chain ID replay protection | EIP-155 (Simple replay attack protection) | Adds chain ID to the transaction signing data so a tx signed for mainnet can't be replayed on a testnet. |

### Transaction Types

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| Legacy transactions | Ethereum Yellow Paper §4; EIP-155 | The original transaction format. Still widely used. |
| EIP-1559 transactions | EIP-1559 (Fee market change for tx fee market) | Replaces the auction-based gas model with a base fee + priority fee. The standard for post-London Ethereum. |
| EIP-2930 transactions | EIP-2930 (Optional access lists) | Pre-declares storage slots to access, saving gas on cross-contract calls. Type-1 transaction envelope. |

### EIP-712 Typed Data

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| EIP-712 typed structured data | EIP-712 (Ethereum typed structured data hashing and signing) | Standard for signing human-readable structured data (not raw bytes). Lets wallets display what the user is signing. Used by SIWE, permit2, and most modern dApp signing. |
| EIP-191 signed data prefix | EIP-191 (Signed Data Standard) | Defines the `\x19` prefix byte that separates signed messages from transactions. EIP-712 builds on this. |

### Signing & Address Derivation

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| secp256k1 signing | SEC 2 v2; RFC 6979 (deterministic nonce); EIP-2 (low-s) | All crypto primitives come from `trust`. `chain` wraps them for EVM-specific encoding. See SPEC-001 for the full standard citations. |
| Ethereum address derivation | EIP-55 (Mixed-case checksum address encoding) | Adds a checksum to Ethereum addresses so typos are caught. We validate checksums on all address inputs. |

### Anchoring

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| Content-addressed anchoring | No formal standard — pattern from Chainpoint, OpenTimestamps, ENS | Anchoring a hash on-chain creates a public, timestamped proof of existence. The pattern is well-established even without a single governing RFC. |
| Merkle root anchoring | RFC 6962 §2.1 (Merkle tree structure) | One on-chain transaction anchors N off-chain attestations via their Merkle root. The root is stored; individual proofs verify off-chain. |

### RPC

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| JSON-RPC 2.0 | JSON-RPC 2.0 Specification | The wire protocol every Ethereum node speaks. `eth_call`, `eth_sendRawTransaction`, `eth_getLogs`, etc. |
| Ethereum JSON-RPC API | Ethereum Wiki — JSON-RPC API | The specific method set for Ethereum: `eth_*`, `net_*`, `web3_*`. |

### Contract ABI

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| Contract ABI | Solidity ABI Specification (Ethereum) | Defines how to encode function calls and decode return values. Without this, we can't call the anchor contract or parse event logs. |

### Military-Grade & National Security References

Blockchain anchoring is not a NIST/NSA-recognized security control, but the
underlying primitives (secp256k1, Keccak-256) and the tamper-evidence properties
of on-chain anchors have analogs in federal standards. Cite where applicable.

| Capability | Standard | Applicability |
|------------|----------|---------------|
| secp256k1 signing | Not in CNSA 2.0 or FIPS 186-5 | secp256k1 is not an NIST/NSA-approved curve. EVM signatures cannot be used in NSS systems. Note the gap in Godoc — a federal consumer needing on-chain anchoring would need a NIST-curve adapter (future work). |
| On-chain tamper evidence | SP 800-53 Rev5 SI-7 (Software & Firmware Integrity) | Anchoring a content hash on-chain provides a public, append-only integrity check — analogous to SI-7 integrity monitoring. Cite when describing the anchor's security property. |
| Merkle root anchoring | SP 800-53 Rev5 SC-8 (Transmission Confidentiality & Integrity) | A Merkle root anchored on-chain provides batch integrity verification — analogous to SC-8 integrity for a set of attestations. Cite on anchor-verification functions. |
| Key management for wallet keys | SP 800-57 Rev5 (Recommendation for Key Management) | Wallet private keys are long-lived signing keys. NIST key management guidance applies to their generation, storage, and rotation. Cite on wallet key-generation functions. |

## Linked Plan

- Plan: `plans/PLAN-003.md` (created by Architect)
- Tasks: listed in the plan under Workstreams

## Source Material

- `Go Trust & Security Platform — Architecture Specification.md` (root) — Module 3: chain
- `spec/00-thesis.md` (root) — chain module boundary
- `ghost-protocol/backend/internal/wallet/service.go` — SIWE flow (the EIP-191 signature
  verification pattern informs how `chain` wraps `trust` secp256k1 recovery)
- build-web3 skill — EVM/EIP-712/QuickNode adapter guidance, HyperCore streams,
  agent identity (ERC-8004), RPC reference
