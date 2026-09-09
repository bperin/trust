# AGENTS.md — trust workspace

> **Architecture:** Three Go modules with one-way dependency:
> `auth → trust ← chain`. Trust is the cryptographic core with zero
> deps on the other two. See
> [`.ai-trust/context/architecture/architecture.md`](.ai-trust/context/architecture/architecture.md)
> for the full breakdown — modules, code structure, components,
> dependencies, data ownership, realtime/events/channels, deployment,
> and skills.

## Modules

| Module | Path | Import | Purpose |
|--------|------|--------|---------|
| trust | `trust/` | `github.com/bperin/trust` | Crypto primitives, identity, proofs, credentials, attestations |
| auth | `auth/` | `github.com/bperin/auth` | OIDC, OAuth2, WebAuthn, sessions, claims |
| chain | `chain/` | `github.com/bperin/chain` | EVM, Ethereum, wallet, EIP-712, RPC, QuickNode |

## Dependency rule

```
auth ──────┐
            ▼
          trust
            ▲
            │
          chain
```

- `trust` must never import `auth` or `chain`.
- `auth` may import `trust`.
- `chain` may import `trust`.
- `auth` and `chain` do not depend on each other.

## Quick reference

| Task | Command |
|------|---------|
| Build all | `go build ./...` (from each module) |
| Test all | `go test ./...` (from each module) |
| Vet | `go vet ./...` (from each module) |
| Tidy | `go mod tidy` (from each module) |
| Add trust dep to auth | `cd auth && go get github.com/bperin/trust` |
| Add trust dep to chain | `cd chain && go get github.com/bperin/trust` |

## Branching

Two branches. No worktrees. No feature branches. No release branches.

| Branch | Purpose | Rules |
|--------|---------|-------|
| `master` | Production. What gets tagged and released. | Protected. No direct push. No force push. PR only. All checks must pass before merge. |
| `dev` | Active development. Where work happens. | Direct push is fine. This is the default branch for all work. |

- Work on `dev`. Commit to `dev`. Push to `dev`.
- To ship to `master`, open a PR from `dev` to `master`. Squash or rebase
  merge — your call, but keep the history readable.
- Never force push to `master`. Never commit directly to `master`.
- No git worktrees. They fragment context and make the agent lose track of
  which branch it's on. One checkout, one branch at a time.
- No feature branches off `dev`. If a change is big enough to need a branch,
  it's big enough to need a spec and a plan first — and the work still
  happens on `dev` under that plan.
- Branch protection is enforced server-side on `master` (PR required, no
  force push, no deletion). `dev` is unprotected for direct push.
- **Plan completion:** when all tasks in a plan are `done`, commit all
  remaining files on `dev`, then open a PR from `dev` to `master` and
  squash-merge. The PR title is the plan name (e.g. `PLAN-001: primitive
  wrappers`). The PR body lists the completed tasks and their standards.
  Run `govulncheck ./...` before opening the PR. All CI checks must pass
  before merge.

## Project context

The `.ai-trust/` directory is the durable context layer. It is the
source of truth for specs, plans, tasks, decisions, architecture, and
workflow protocols. A fresh session reads these files instead of
relying on conversation history.

| Path | Purpose |
|------|---------|
| `.ai-trust/AGENTS.md` | Workflow protocol — how specs, plans, tasks, and PRs are reviewed and merged |
| `.ai-trust/STATE.md` | Current execution state — what's done, what's active, what's next |
| `.ai-trust/DECISIONS.md` | ADR index — architectural decisions and their status |
| `.ai-trust/context/identity/project.md` | Project identity — name, stack, modules, repo |
| `.ai-trust/context/architecture/architecture.md` | Full architecture breakdown — modules, code structure, components, dependencies, data ownership, realtime/events, deployment, skills |
| `.ai-trust/context/specs/SPEC-NNN.md` | Specs — what the system must do |
| `.ai-trust/context/plans/PLAN-NNN.md` | Plans — how the system is built, broken into workstreams |
| `.ai-trust/context/tasks/TASK-NNN.md` | Tasks — the implementation contract for one unit of work |
| `.ai-trust/context/workflows/*.md` | Workflows — the review and implementation pipeline (with mermaid diagrams) |
| `.ai-trust/context/state/overview.xlsx` | Generated spreadsheet — all specs, plans, tasks, architecture, decisions, workflows in one workbook |
| `.ai-trust/context/state/current.md` | Current state summary |

### Persistent UUIDs

Every spec, plan, and task has a persistent UUID in its `## Status`
section. UUIDs are deterministic (v5 from the human-readable ID) and
never change. The `overview.xlsx` reads them from the markdown files.

### overview.xlsx

The spreadsheet is **generated**, not maintained. Run the
`project-context` tool to rebuild it from the markdown files and git
metadata:

```bash
cd /Users/brian/code/project-context
node bin/cli.js overview -w .ai-trust -t /Users/brian/code/trust
```

The workbook contains sheets for: Identity, Specs, Plans, Tasks,
Modules, Code Structure, Components, Dependencies, Data Ownership,
Realtime/Events/Channels, Deployment, Skills (always-on, on-demand
project-local, on-demand user-level), Decisions, and Workflows.

### Session spawning

When a task is marked done, the next session should start fresh with
the durable context. Read `.ai-trust/STATE.md` and the next task's
markdown file — they carry everything needed to continue without
conversation history.

## Conventions

- **Go style:** explicit dependency wiring, no DI framework. Constructor
  functions (`NewXxx`) return concrete types. Interfaces defined on the
  consumer side.
- **Godoc:** all exported declarations have Godoc comments. See the
  [Godoc Rules](#godoc-rules) section below for the full standard — format,
  standard citations, and military-grade references.
- **Errors:** sentinel errors checked with `errors.Is`. Wrap with
  `fmt.Errorf` and `%w` at boundaries.
- **Logging:** `log/slog` with structured fields.
- **Testing:** see [Testing Rules](#testing-rules) below — over-the-top,
  lowest-level-domain-up, no skipped tests, known vectors for every crypto
  primitive.
- **No reflection-based runtime DI.** No uber/fx, uber/dig.
- **No interface inflation.** Expose concrete structs; define interfaces
  near the consumer only when there are multiple implementations.
- **No premature DRY.** A little duplication is far cheaper than the wrong
  abstraction. Don't extract shared code until the third occurrence proves
  the pattern.
- **No VIPER / Clean Architecture layering.** No presentation/domain/data
  layer fragmentation. No mapper boilerplate. Flat, capability-focused
  packages. Domain logic is pure; infrastructure adapters sit at the edges.
- **SOLID where it earns its keep:** single responsibility (one package =
  one capability), open/closed (extend via new types, not by editing
  existing ones), Liskov (interfaces document behavioral contracts),
  interface segregation (consumer-side, small), dependency inversion
  (domain depends on interfaces, infra implements them). But don't
  force SOLID where a concrete struct is simpler.
- **Security:** never log or commit secrets, private keys, or credentials.
  Use `crypto/rand` for all random generation — never `math/rand`. Use
  `crypto/subtle.ConstantTimeCompare` for all security-sensitive
  comparisons. Never trust the `alg` header of incoming JWTs — whitelist
  per key, reject `alg: none`. Validate `exp`, `nbf`, `iat`, `iss`, `aud`
  on every token. Use cryptographically random `state` parameters in
  OAuth2 redirect flows.
- **Commits:** never author as Devin or any AI co-author. The
  `prepare-commit-msg` hook (`.githooks/`) strips AI co-authorship lines
  automatically. Before committing, humanize the commit message by invoking
  the `content-humanizer` skill — strip AI filler words, vary sentence
  rhythm, and write like a person. Commit messages should be concise and
  sound human, not machine-generated.

## Skill-Gated Implementation

No algorithm, security primitive, or auth flow is implemented unless a skill
with definitive source knowledge is loaded and its guidance is followed. This
prevents guessing at crypto and auth implementations.

**Always-on skills** (load at session start, keep in context):

| Skill | Source | Why |
|-------|--------|-----|
| `go-systems-programmer` | user-level | Explicit wiring, stdlib-first, consumer-side interfaces, boring main |
| `go-security-expert` | user-level | alg enforcement, claim validation, CSRF/state, constant-time, crypto/rand |
| `go-memory-oom-guard` | user-level | Key material lifetime, memory leaks in long-running processes |

**On-demand skills** (load when the trigger condition is met, not before):

| Skill | Source | Trigger |
|-------|--------|---------|
| `go-code-review` | user-level | Before any PR — run `gofmt`, `go vet`, `golangci-lint`, review checklist |
| `build-web3` | user-level | When implementing `chain/` — EVM, EIP-712, QuickNode adapter, RPC patterns |
| `golang-security` | project-local (`.agents/skills/`) | When writing crypto/auth code — injection prevention, secrets, SSRF |
| `golang-testing` | project-local | When writing tests — table-driven, fuzzing, fixtures, goroutine leak detection |
| `golang-code-style` | project-local | When writing or reviewing Go code for style |
| `golang-error-handling` | project-local | When designing error boundaries — wrapping, sentinels, slog |
| `golang-concurrency` | project-local | When writing concurrent code — nonce stores, session caches, key registries |
| `golang-performance` | project-local | When profiling shows a bottleneck — allocation, pooling, hot-path |
| `wycheproof` | project-local | When testing crypto — known attack vectors from Trail of Bits |
| `implementing-digital-signatures-with-ed25519` | project-local | When implementing Ed25519 — key generation, signing, verification |
| `ethereum` | project-local | When implementing Keccak-256 or secp256k1 — Ethereum context, EIPs |

**Algorithm-to-skill matrix** — the authoritative mapping lives in
`trust/algorithms.json` under each algorithm's `skill` field. When a plan
targets an algorithm, the plan must list the primary and secondary skills
that will be loaded for that workstream. Do not load all skills at once —
load only what the current workstream needs.

| Algorithm | Primary | Secondary |
|-----------|---------|------------|
| sha-256, sha-3, blake3 | `golang-performance` | `wycheproof` (where vectors exist) |
| keccak-256 | `ethereum` | `golang-performance` |
| hkdf-sha256 | `golang-security` | — |
| aes-256-gcm, xchacha20-poly1305 | `wycheproof` | `golang-security` |
| aes-kw, hpke | `golang-security` | `wycheproof` |
| x25519 | `wycheproof` | `golang-security` |
| ed25519 | `implementing-digital-signatures-with-ed25519` | `wycheproof`, `golang-security` |
| secp256k1 | `ethereum` | `wycheproof`, `golang-security` |
| rsa-pss, ecdsa-p256, ecdsa-p384 | `wycheproof` | `golang-security` |
| csprng | `golang-security` | — |

**Per-commit standard citation:** every commit that implements or modifies a
cryptographic algorithm or auth flow must cite the governing standard in the
commit message body. Example:

```
implement aes-256-gcm encrypt/decrypt with nonce management

Implements [SP 800-38D] §7.1 — AES-256-GCM authenticated encryption.
Nonce is 96-bit random, prefixed to ciphertext, AAD binds version/type.
Meets [CNSA 2.0] AES-256 requirement for TOP SECRET.

Test vector: NIST GCM Test Case 3.
```

The citation must match the `godoc_citation` field in `trust/algorithms.json`.
If the algorithm is not in the registry, add it first.

**Plan rule:** when building a plan (`PLAN-NNN.md`), each workstream that
implements an algorithm must:
1. List the algorithm IDs from `trust/algorithms.json` that the workstream covers.
2. List the primary and secondary skills that will be loaded for those algorithms.
3. Confirm the skills are installed (check `.agents/skills/` or user-level).
4. If a skill is missing, install it (`npx skills find "<query>"` then
   `npx skills add <owner/repo@skill> -y`) before starting the workstream.

## Testing Rules

Testing is over-the-top. Every layer is tested from the lowest-level domain
primitive upward. No test may go green by skipping.

### Universal rules (all tiers)

1. **Negative tests for every failure mode.** For every success path, there
   is a test for the failure path: wrong key, tampered ciphertext, expired
   token, revoked attestation, wrong nonce, high-s signature, modified
   payload. If it can fail, it has a test that proves it fails.

2. **Boundary tests.** Test the edges: empty input, max-size input, nil
   values, single-byte data, oversized nonces, expired-but-not-yet-valid
   tokens. Boundaries are where bugs live.

3. **Cross-module isolation tests.** Verify dependency rules by grep:
   `trust/` has no `auth` or `chain` imports. `auth/` has no `chain`
   imports. These are test functions that fail if the rule is violated.

4. **No skipped tests.** `t.Skip` on missing dependencies is forbidden in
   any suite cited as evidence. DB-backed or network-backed tests are gated
   behind build tags and fail when their dependency is unreachable — they
   do not silently pass.

5. **Table-driven.** Every test is table-driven with named cases. Failure
   messages include: what was wrong, the input, got, want. Order is
   `got != want`.

6. **Test next to source.** `*_test.go` files live next to the code they
   test. No separate test packages. Use `_test` package suffix for
   black-box tests when needed.

7. **govulncheck in CI.** Run `govulncheck ./...` before merge. Any known
   vulnerability in a dependency blocks the merge.

8. **Race detector.** `go test -race ./...` passes. Any shared state
   (nonce stores, session caches, key registries) is tested under the
   race detector.

9. **Constant-time comparison.** Security-sensitive comparisons in tests
   use `crypto/subtle.ConstantTimeCompare`. Never `==` or `bytes.Equal` for
   keys, digests, ciphertexts, or tokens.

### Tier 1 — Primitives (hash, AEAD, KDF, key exchange, signatures)

10. **Known vectors from the standard.** Every primitive has a test that
    feeds a known input and asserts the exact output from the standard's
    test vector suite. Cite the vector source in the test comment:
    `// Vector: [RFC 8032] Test Vector 1`.

11. **Round-trip tests.** Every encrypt/decrypt, sign/verify pair has a
    round-trip test: produce then consume and assert equality of the
    recovered value.

12. **Wycheproof where vectors exist.** If Project Wycheproof has attack
    vectors for the algorithm (AES-GCM, RSA, ECDSA, ECDH, Ed25519), add
    Wycheproof tests. These catch edge cases the standard vectors miss.

13. **Determinism tests.** Same input + same key produces the same output.
    For deterministic algorithms (Ed25519, Keccak-256), this is a hard
    equality. For randomized algorithms (AES-GCM with random nonce), test
    that the ciphertext differs but decryption round-trips.

### Tier 2 — Compositions (envelope encryption, HPKE, key recovery)

14. **Composition round-trip.** Full cycle through all composed primitives.
    HPKE: sender setup → seal → receiver open → recover plaintext. Envelope:
    generate DEK → encrypt payload → wrap DEK with KEK → unwrap → decrypt.
    The round-trip proves the wiring is correct end-to-end.

15. **Protocol-level known vectors.** Compositions that have their own RFC
    (HPKE RFC 9180, AES-KW RFC 3394) test against the RFC's test vectors —
    not just the underlying primitive vectors. The composition has its own
    wire format and KDF chain; those need independent verification.

16. **Error propagation.** When an underlying primitive fails, the
    composition must surface a meaningful error. Test that a corrupted
    wrapped key, a wrong KEK, or a tampered HPKE envelope produces an error
    from the right layer — not a panic, not a silent nil.

17. **Cross-primitive integration.** Verify the composition calls primitives
    in the right order with the right parameters. HPKE must use X25519 →
    HKDF → AEAD in that order with the right info string. This is tested by
    the protocol-level vectors — if the order or parameters are wrong, the
    vector won't match.

### Tier 3 — Identity, proofs, and attestations (DID, X.509, JWK, Merkle, VC)

18. **Parse/serialize round-trip.** Parse a known document, re-serialize,
    and verify byte-identical or semantically equal output. For canonical
    formats (JWK, X.509 DER), bytes must match. For JSON-LD formats (VC,
    DID), canonicalize first, then compare.

19. **Cross-implementation vectors.** Parse documents produced by other
    libraries or standards (W3C VC test suite, DID spec test suite, RFC
    7517 JWK examples). This catches parser bugs that self-consistent
    round-trips miss — if you only parse your own output, you can both
    produce and parse the same wrong format.

20. **Canonicalization determinism.** Same logical document always
    canonicalizes to the same bytes. Two different byte-level
    representations of the same VC must produce the same canonical form.
    This is what makes signatures verifiable across implementations.

21. **Verification negative tests.** Tampered proof, revoked credential,
    expired attestation, wrong issuer, wrong subject, mismatched proof
    type. Each failure mode has a test that proves verification rejects it.

22. **Cross-reference tests.** An X.509 cert signed with RSA verifies
    through the RSA wrapper. A `did:pkh` resolves through secp256k1
    recovery. A Merkle proof verifies through the hash wrapper. These
    tests prove the identity layer actually uses the primitive layer —
    not a parallel implementation.

### Tier 4 — Auth flows (JWT, OIDC, OAuth2, WebAuthn, SIWE, sessions)

23. **Full flow tests.** Complete lifecycle: issue → validate → refresh →
    revoke for JWT; discover → authorize → token → userinfo for OIDC;
    register → login for WebAuthn. The flow test exercises the real
    sequence, not just individual functions in isolation.

24. **HTTP handler tests.** Request/response shape, status codes, error
    bodies. Use `httptest.NewRecorder` or `httptest.NewServer`. No live
    network calls — mock the upstream provider.

25. **Negative flows.** Expired token, wrong issuer, wrong audience,
    replayed nonce, revoked session, wrong `alg` header, `alg: none`
    rejection, missing claims. Each attack vector has a test.

26. **Contract tests.** OIDC discovery response matches the spec. OAuth2
    token response has the required fields. JWT claims match RFC 7519.
    These are schema/shape tests against the standard, not just
    round-trips.

27. **Build-tag-gated provider integration.** Tests that hit a real OIDC
    provider or OAuth2 endpoint are gated behind a build tag
    (`//go:build integration`) and fail when the provider is unreachable.
    They do not silently pass. Unit tests use fakes/mocks for speed.

## Module: trust

Pure cryptographic primitives. No application logic. No HTTP. No DB.

### Packages

| Package | Purpose |
|---------|---------|
| `crypto/hash` | SHA-256, SHA-3, Keccak-256, BLAKE3 wrappers with consistent API |
| `crypto/aead` | AES-256-GCM, XChaCha20-Poly1305 with internally generated random nonces |
| `crypto/envelope` | Envelope encryption — KEK/DEK separation, AES-KW (RFC 3394) |
| `crypto/hkdf` | HKDF-SHA256 key derivation |
| `crypto/ed25519` | Ed25519 key generation, sign, verify |
| `crypto/secp256k1` | secp256k1 sign, verify, public-key recovery, EVM address derivation |
| `crypto/rsa` | RSA sign/verify (PKCS1-v1_5, PSS) for X.509/OIDC/JWKS interop |
| `crypto/ecdsa` | ECDSA P-256/P-384 sign/verify for X.509/OIDC/JWKS interop |
| `crypto/x25519` | X25519 ECDH key exchange |
| `crypto/rand` | Secure random byte generation (raw primitive only) |
| `identity/did` | W3C DID parsing, resolution interface |
| `identity/didpkh` | did:pkh — blockchain account DIDs (uses secp256k1 recovery + Keccak-256) |
| `identity/x509` | X.509 certificate parsing and verification (path validation, EKU, revocation) |
| `identity/jwk` | JWK/COSE/JOSE key serialization and JWS structures |
| `merkle` | Merkle tree construction, inclusion proofs, verification |
| `signature` | Multi-sig, threshold signatures, aggregation |
| `credential` | W3C Verifiable Credentials data model |
| `attestation` | Attestations with canonicalization, domain separation, validity, revocation |

## Module: auth

User/service authentication. Depends on trust for identity types and crypto primitives.

### Packages

| Package | Purpose |
|---------|---------|
| `jwt` | JWT issuer/validator — HS256 + RS256/ES256/EdDSA, JWKS, alg whitelisting |
| `password` | bcrypt password hashing and verification |
| `oidc` | OpenID Connect discovery, token validation, userinfo |
| `oauth` | OAuth2 authorization code flow, PKCE, refresh-token rotation |
| `webauthn` | Passkey registration and login (WebAuthn) |
| `siwe` | Sign-In with Ethereum (EIP-4361) — nonce, verify, JWT issuance |
| `session` | Server-side session store, cookie management, revocation |
| `claims` | JWT/OIDC claim parsing, validation, scope/role enforcement |

## Module: chain

Blockchain integration. Depends on trust for crypto (secp256k1, Keccak-256) and Merkle.

### Packages

| Package | Purpose |
|---------|---------|
| `evm` | EVM transaction building, signing, RLP encoding |
| `ethereum` | Ethereum types, constants, address derivation |
| `wallet` | Key management, signing, address derivation from secp256k1 |
| `eip712` | EIP-712 typed structured data hashing and signing |
| `rpc` | JSON-RPC client abstraction, batch requests |
| `quicknode` | QuickNode provider adapter (HyperCore streams, etc.) |

## Godoc Rules

### 1. Standard Godoc conventions

Every exported declaration — package, function, type, method, constant, variable —
has a Godoc comment immediately preceding it (no blank line between comment and
declaration).

- **Comment starts with the declaration name.** `// Hash computes...` not
  `// This function computes...`. Godoc renders this as a sentence.
- **Complete sentences.** Period at the end. No fragments.
- **Package comment** goes on the package clause (`// Package hash implements...`)
  or in a `doc.go` file for longer overviews.
- **No redundant phrasing.** Don't write `// The Hash function hashes data.` —
  write `// Hash returns the SHA-256 digest of data.`
- **Grouped declarations** (var/const blocks) get a block comment, and individual
  entries get inline comments if they need explanation.
- **Unexported declarations** get comments when their purpose isn't obvious from
  the name and surrounding context.

### 2. Standard citations

Every exported declaration that implements, wraps, or conforms to a formal standard
must cite that standard inline as the first thing in the comment:

```go
// IssueAccessToken implements [RFC 7519] §4.1 — mints a signed JWT whose
// subject is userID. Returns the compact serialization header.payload.signature.
func (t *TokenIssuer) IssueAccessToken(userID string, ...) (string, error)
```

```go
// Sign implements [RFC 8037] §5.1.6 (Ed25519) — produces a 64-byte detached
// signature over message. Deterministic: same key + message always yields the
// same signature. No nonce to misuse.
func (k *Ed25519Key) Sign(message []byte) ([]byte, error)
```

**Citation format:**
- `[RFC NNNN]` for IETF RFCs, with section number if specific (§4.1)
- `[FIPS NNN-N]` for NIST FIPS publications (e.g., `[FIPS 180-4]`)
- `[SP 800-NN]` for NIST Special Publications (e.g., `[SP 800-38D]`)
- `[EIP-NNN]` for Ethereum Improvement Proposals
- `[W3C SPEC]` for W3C recommendations (e.g., `[W3C VC-DM v2.0]`)
- `[SEC N vN]` for SEC standards (e.g., `[SEC 2 v2]`)
- `[BIP-NN]` for Bitcoin Improvement Proposals
- `[CWE-NNN]` for MITRE CWE entries

**After the citation, state the plain-language rationale** — what problem this
solves, why this primitive exists in this platform, in one or two sentences.

If a declaration implements a known test vector from the standard, cite the
specific test case: `// Matches [RFC 8032] Test Vector 1 (TESTSHA).`

If no formal standard exists (e.g., BLAKE3), cite the specification document:
`// Implements [BLAKE3 Spec, 2020] — the BLAKE3 hash function...`

### 3. Military-grade and national security references

When a primitive or function meets or is governed by a national security standard,
add a second citation line immediately after the standard citation:

```go
// Encrypt implements [SP 800-38D] §7.1 (AES-256-GCM) — authenticated encryption
// with a 96-bit random nonce prefixed to ciphertext.
// Meets [CNSA 2.0] AES-256 requirement for TOP SECRET systems.
// FIPS 140-3 validated when used with a FIPS-approved module.
func (e *AESGCM) Encrypt(plaintext, aad []byte) ([]byte, error)
```

**Military/national security standards to cite where applicable:**

| Standard | When to cite |
|----------|--------------|
| `[CNSA 2.0]` (NSA Commercial National Security Algorithm Suite 2.0, 2022) | When a primitive meets TS requirements: AES-256, SHA-384, RSA ≥3072, ECDSA P-384. Note when a primitive does NOT meet CNSA (e.g., X25519, Ed25519 are not in CNSA 2.0). |
| `[FIPS 140-3]` (Cryptographic Module Validation) | When a function's correctness depends on a FIPS-validated module. Note that Go's stdlib is NOT FIPS-validated by default; FIPS mode requires a certified build (e.g., `GOEXPERIMENT=boringcrypto`). |
| `[CNSSP 15]` (National Policy on AES for NSS) | When citing AES-256 for national security system use. |
| `[SP 800-53]` (Security Controls for Federal Systems) | When a function implements a specific control: SC-13 (cryptographic protection), IA-2 (multi-factor), IA-5 (authenticator management). |
| `[SP 800-63B]` (Digital Identity Guidelines) | When an auth function maps to an AAL level (AAL1/AAL2/AAL3). |
| `[SP 800-171]` (Protecting CUI) | When a function protects controlled unclassified information. |
| `[CSfC]` (NSA Commercial Solutions for Classified) | When layered crypto (e.g., envelope encryption) implements a CSfC component. |
| `[DoD STIG]` (Security Technical Implementation Guide) | When a function enforces a STIG requirement (session timeout, password complexity, key length). |

**When a primitive does NOT meet a national security standard, say so:**

```go
// SharedSecret implements [RFC 7748] §6.1 (X25519 ECDH) — derives a 32-byte
// shared secret from a private key and peer public key.
// NOTE: X25519 is not in [CNSA 2.0]; national security systems require
// P-384 ECDH per [SP 800-56A Rev3].
func SharedSecret(priv *X25519PrivateKey, peerPub []byte) ([]byte, error)
```

This is not a warning — it's documentation. A consumer building a TS system
needs to know they must swap to P-384. A consumer building a commercial product
can use X25519 freely.
