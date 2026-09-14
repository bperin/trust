# Trust Workspace Product Contract

## Purpose

The `trust` workspace is reusable security infrastructure for Go applications.
Its four modules provide boring, testable building blocks for cryptographic
identity and proof (`trust`), authentication (`auth`), EVM interaction
(`chain`), and remote-KMS signing mechanics (`kms`).

The `github.com/bperin/trust/trust` module is the dependency-free
cryptographic core; the workspace as a whole also contains the one-way
consumers `auth`, `chain`, and `kms`. None of the four is the Trakt protocol,
and none may know what a brand, SKU, price, inventory record, recommendation,
or purchase means.

## Consumers

- Go services that need vetted cryptographic operations and wire formats.
- Authentication systems that need standards-based token and flow mechanics.
- Protocol libraries such as `trakt2-crypto` that compose generic trust
  primitives into a product-specific protocol.
- Chain-aware applications that need EVM encoding, signing, verification, and
  provider-neutral RPC access.

## Module products

### `github.com/bperin/trust/trust`

Owns algorithms and generic composition concepts: canonical encoding, hashes,
signatures, key representations, evidence references, identity, authority,
delegation, claims, credentials, attestations, proofs, Merkle commitments, and
offline verification.

It has no dependency on `auth`, `chain`, `kms`, or a product repository.

### `github.com/bperin/trust/auth`

Owns generic authentication mechanics: bcrypt password verification,
CSPRNG-generated tokens, JWT claims issuance and validation (RFC 7519),
OAuth2 grant flows with PKCE (S256 only) and refresh-token rotation, and
sessions with related consumer-side storage interfaces.

It may depend on `trust`. It does not own Trakt users, memberships, billing
status, organization policy, HTTP routes, or persistence implementations.

OIDC discovery/userinfo and WebAuthn are not implemented. They are planned
capabilities, not shipped — see [Shipped vs. planned](#shipped-vs-planned).

### `github.com/bperin/trust/chain`

Owns generic EVM mechanics: transaction codecs and verification, addresses,
wallet signing, EIP-712, ABI primitives, JSON-RPC transport, and provider
adapters where they remain reusable.

It may depend on `trust`. It does not own Trakt anchors, Trakt contract policy,
gas sponsorship decisions, publishing workflows, or transaction history.

`chain` should expose the smallest provider-neutral interfaces and deterministic
codecs consumers need. It should not grow a home-built replacement for managed
node hosting, event pipelines, historical indexes, backfill systems, endpoint
administration, or usage monitoring. Those are infrastructure-adapter concerns;
Trakt can satisfy them with its paid QuickNode account.

### `github.com/bperin/trust/kms`

Owns the remote-KMS signing core: a `RemoteSigner` interface over a
pre-hashed 32-byte digest, DER ECDSA-Sig-Value parsing with low-s
normalization (EIP-2), X.509 SubjectPublicKeyInfo parsing for secp256k1
public keys, and recovery-id computation for EVM signatures. It is pure
parsing, validation, and interface — no private key material ever enters the
process, and the default build carries no cloud provider coupling.

It may depend on `trust` only. It does not import `auth` or `chain`.

The AWS and GCP provider adapters live in the private `trakt2-crypto`
repository (`internal/kms/aws`, `internal/kms/gcp`) behind the `aws_kms` and
`gcp_kms` build tags. They are not part of this shipped product surface.

## Boundary test

A capability belongs here only if a second unrelated application could use it
without importing Trakt vocabulary or adopting Trakt business policy.

Examples:

| Capability                                                          | Boundary                                        |
| ------------------------------------------------------------------- | ----------------------------------------------- |
| Ed25519 signing                                                     | `trust`                                         |
| Canonical JSON and deterministic CBOR                               | `trust`                                         |
| Generic scoped delegation                                           | `trust`                                         |
| Generic attestation and offline proof verification                  | `trust`                                         |
| OAuth2 grant mechanics                                              | `auth`                                          |
| Trakt membership and login eligibility                              | Trakt API                                       |
| EVM transaction encoding and sender recovery                        | `chain`                                         |
| DER/SPKI parsing and recovery-id computation for remote-KMS signing | `kms`                                           |
| Cloud KMS credentials, key lifecycle, and provider wiring           | Application adapter in `trakt2-crypto`          |
| Hosted RPC nodes, event streams, and historical chain indexing      | Managed provider through an application adapter |
| `product.attest` capability semantics                               | `trakt2-crypto`                                 |
| Trakt product claim schema                                          | `trakt2-crypto`                                 |
| Catalog persistence and product search                              | Trakt API                                       |

## What Trakt requires from trust

- Stable canonical encodings with golden vectors.
- Content hashing and domain-separated signature inputs.
- Portable public-key identifiers and representations.
- Generic organization identity and key-rotation building blocks.
- Delegation with capability, resource scope, validity, and revocation inputs.
- Generic claim, attestation, evidence, proof, and commitment types.
- Offline verification with explicit results rather than one opaque boolean.
- Merkle inclusion proofs when batching becomes necessary.
- EVM signing and transaction verification through `chain`.
- Standards-based user/service authentication through `auth`.
- Remote-KMS secp256k1 signing mechanics — DER/SPKI parsing and recovery-id
  computation — through `kms`.

Trakt should first describe a missing generic capability here as a consumer
contract. It should only be added after proving that the behavior is not
Trakt-specific.

## Release contract

- Each Go module is independently consumable from an immutable published
  version.
- Module-path tag naming must work with the repository's multi-module layout.
- A released consumer must build without local filesystem `replace` directives.
- Breaking wire or verification changes require a deliberate version boundary.
- Published documentation distinguishes cryptographic validity from factual or
  business validity.

## Non-goals

- Operating a hosted identity, key, registry, or RPC service.
- Defining commercial product schemas.
- Owning application persistence, HTTP APIs, queues, tenancy, or billing.
- Recreating broad wallet or blockchain SDKs without a concrete reusable need.
- Claiming that a signature establishes real-world truth.

## Shipped vs. planned

Everything in [Module products](#module-products) above is implemented and
tested in the tree. The following are planned or deferred and must not be
treated as shipped:

- OIDC discovery, userinfo, and ID-token flows (`auth`).
- WebAuthn registration and authentication (`auth`).
- Cloud KMS provider adapters — the AWS/GCP packages live in the private
  `trakt2-crypto` repository behind opt-in build tags, not in this repo.
- Hosted chain infrastructure — managed RPC nodes, event pipelines,
  historical indexing — stays with providers and application adapters, not
  library code.

## Current product questions

- Which existing organization, authority, attestation, and proof APIs are stable
  enough to publish for an external protocol consumer?
- What tag convention and release process will publish all required submodules
  correctly?
- Which chain lifecycle helpers are genuinely reusable and which should remain
  in application adapters?
- Which existing RPC, polling, event, and indexing code duplicates QuickNode
  services without adding protocol value?
- Should applications import `auth` broadly, or restrict it to dedicated auth
  adapters and composition roots?

## Product maturity

```yaml
maturity:
  level: product
  completeness: 80
  blockers:
    - "The multi-module release and compatibility policy is not fully established."
    - "The public stability level of generic authority and proof APIs is not declared."
  safe_to_refine:
    - "Published-module release contract"
    - "Trakt consumer coverage matrix"
    - "Package-level boundary tests"
```
