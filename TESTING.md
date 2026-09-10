# Testing Audit

Audit of the current test suite against the standards in `AGENTS.md`
(Testing Rules + algorithm-to-skill matrix) and the `go-code-review`
and `golang-testing` skills. Findings are grouped by severity:
**Must Fix**, **Should Fix**, **Nits**.

Scope at audit time: only `trust/crypto/*` has implementation and
tests. `trust/{attestation,credential,identity,merkle,signature}` and
the entire `auth/` and `chain/` modules are empty (no `.go` files).
12 test files, 3,287 lines of tests, 18 source files, 4,210 lines.

## Snapshot

| Package      | Coverage  | Test files | Wycheproof | Vectors cited |
|--------------|-----------|------------|-----------|---------------|
| hash         | 100.0%    | 5          | —         | FIPS 180-4, FIPS 202, BLAKE3 spec, Keccak-256 |
| secp256k1    | 97.9%     | 1          | yes       | RFC 6979 (dcrd), Wycheproof |
| x25519       | 95.1%     | 1          | partial   | RFC 7748 |
| hkdf         | 90.5%     | 1          | —         | RFC 5869 |
| ed25519      | 87.9%     | 1          | yes       | RFC 8032, Wycheproof |
| aead         | 87.8%     | 2          | no        | SP 800-38D, draft-irtf-cfrg-xchacha |
| rand         | 87.5%     | 1          | —         | — |
| **total**    | **93.9%** | **12**     | **2/5**   | |

CI: `.github/workflows/ci.yml` runs gofmt, `go vet`, `go build`,
`go test -race -count=1`, and `govulncheck` per module, plus a nightly
`govulncheck` schedule and a PR dependency-review job.

## What is working well

- **Known-answer vectors from the standards** for every primitive:
  FIPS 180-4 (SHA-256), FIPS 202 (SHA-3), BLAKE3 spec, Keccak-256,
  RFC 5869 (HKDF), RFC 7748 (X25519), RFC 8032 (Ed25519),
  SP 800-38D (AES-GCM), draft-irtf-cfrg-xchacha, and the dcrd RFC 6979
  secp256k1 vectors. Each vector cites its source in a comment.
- **Wycheproof suites** for the two signature schemes that need them
  most (ed25519, ecdsa_secp256k1_sha256), with correct `result` flag
  handling and EIP-2 high-s reconciliation for secp256k1.
- **Constant-time comparison** (`crypto/subtle.ConstantTimeCompare`)
  used consistently for keys, digests, ciphertexts, and signatures.
  No `==`/`bytes.Equal` on secret material anywhere in the suite.
- **Round-trip + negative + boundary** pattern is applied uniformly:
  tampered ciphertext, wrong key, wrong AAD/version, short ciphertext,
  invalid key lengths, empty/nil/large inputs, all-zero signatures.
- **Malleability defenses tested explicitly**: secp256k1 low-s
  enforcement and high-s rejection (EIP-2), X25519 low-order point
  rejection (RFC 7748 §6), AEAD nonce uniqueness over 1000 iterations.
- **`Redact()` leak tests** scan for any 2-byte consecutive raw key
  substring in the redacted output — a genuinely paranoid check.
- **Table-driven with named subtests** throughout; tests live next to
  source; race detector passes clean.
- **govulncheck in CI** with a nightly schedule, satisfying rule 7.

## Must Fix

These violate explicit rules in `AGENTS.md` or would break CI as
configured.

### M1. CI Go toolchain is pinned below the module directive

`.github/workflows/ci.yml` uses `go-version: "1.23"` while every
`go.mod` declares `go 1.27.1`. A module requiring Go 1.27.1 will not
build under Go 1.23 — `go test` fails with
`go.mod requires go >= 1.27.1`. The suite passes locally only because
the dev machine runs `go1.27.1`. CI is almost certainly red (or the
pin is stale). Bump the workflow to `go-version: "1.27.1"` (or a
`>=1.27.1` range). This also gates the `b.Loop()` benchmark API already
in use in `keccak256_bench_test.go`.

### M2. No cross-module isolation tests

`AGENTS.md` Testing Rule 3 (Universal) explicitly requires:

> Cross-module isolation tests. Verify dependency rules by grep:
> `trust/` has no `auth` or `chain` imports. `auth/` has no `chain`
> imports. These are test functions that fail if the rule is violated.

No such test exists. The dependency rule
(`auth → trust ← chain`, `trust` never imports the other two) is a
core architectural invariant and currently has zero executable
enforcement. Add a `TestNoForbiddenImports` (or similar) in each
module that walks its own `.go` files and fails on a forbidden import
path. These belong in a `_test.go` so they run on every `go test`.

### M3. Wycheproof coverage does not match the algorithm-to-skill matrix

`AGENTS.md` defines an algorithm-to-skill matrix that lists Wycheproof
as **primary** for `aes-256-gcm`, `xchacha20-poly1305`, and `x25519`,
and **secondary** for `ed25519` and `secp256k1`. Current state:

| Algorithm        | Matrix role | Wycheproof present? |
|------------------|-------------|---------------------|
| aes-256-gcm      | primary     | **no**              |
| xchacha20-poly1305 | primary   | **no** (one hand-picked vector, not the suite) |
| x25519           | primary     | **no** (only a single low-order-point case) |
| ed25519          | secondary   | yes                 |
| secp256k1        | secondary   | yes                 |

The `xchacha20_test.go` comment references "Wycheproof tcId 1" but
only hard-codes that one vector; the full
`chacha20_poly1305_test.json` suite is not loaded. X25519 has a
hand-written low-order point test but no `x25519_test.json` suite.
Add the Wycheproof JSON to `testdata/` and a loader for AES-GCM,
XChaCha20-Poly1305, and X25519, matching the ed25519/secp256k1
pattern. Rule 12 (Wycheproof where vectors exist) makes this a must.

## Should Fix

Not strict rule violations, but real gaps against the
`golang-testing` skill and the "over-the-top" testing philosophy.

### S1. No `t.Parallel()` anywhere in the suite

Every table-driven test and both Wycheproof runners are sequential.
The Wycheproof subtests (hundreds of cases each) and the independent
crypto round-trip cases are safe to parallelize. Add `t.Parallel()`
inside the `t.Run` closures (and capture `tc := tc` where not already
done — secp256k1 and ed25519 already do `tc := tc`, x25519/hash/aead
do not). This is the single biggest test-wall-time win available.

### S2. No fuzz targets

The wrappers that accept attacker-controlled bytes —
`secp256k1.NewPublicKey` (parses compressed points),
`ed25519.NewPublicKey`/`NewPrivateKey`, `aead.Decrypt` (arbitrary
ciphertext framing), `x25519.NewPublicKey` — are natural fuzz
surfaces. A `FuzzNewPublicKey`/`FuzzDecrypt` that asserts "no panic,
error-or-success only" would harden the parsing paths. The
`golang-testing` skill lists fuzzing as a first-class practice and
`AGENTS.md` rule 9 (race detector) plus the over-the-top philosophy
imply it. Add at least one `FuzzXxx` per parser.

### S3. No `Example` functions

The `go-code-review` checklist and `golang-testing` skill both call
for runnable `Example` functions as executable documentation. A
crypto library is a prime candidate — `ExampleGenerateKey`,
`ExampleEncryptRoundTrip`, `ExampleSignVerify` would document the
canonical usage and fail the build if the API drifts. None exist.

### S4. Uncovered error branches indicate a testability gap

`go tool cover -func` shows untested branches:

- `ed25519.NewPrivateKey` — 40% (the valid-64-byte success path is
  only exercised indirectly via `GenerateKey`/RFC vectors, never by
  calling `NewPrivateKey` with a known 64-byte key directly).
- `secp256k1.NewPublicKey` — 83.3% (the `ParsePubKey` failure branch
  for an unparseable-but-33-byte key is not exercised).
- `GenerateKey` error branches (all three key packages) — the
  `rand.Bytes` failure path is unreachable because `rand.Bytes` is a
  hard-wired concrete call, not an injectable reader.

The `GenerateKey` gap is a design smell: per
`go-systems-programmer` ("consumer-side interfaces", "explicit
dependency wiring"), the CSPRNG should be injectable so the failure
path is testable. At minimum, add a direct `NewPrivateKey`/valid-key
test for ed25519 and a `NewPublicKey`-with-garbage-33-bytes test for
secp256k1 to close the reachable branches.

### S5. No `-shuffle` in CI

`AGENTS.md` rule 3 forbids order-dependent tests. Go 1.17+ supports
`-shuffle=on`; the toolchain is 1.27.1. Add `-shuffle=on` to the CI
`go test` invocation to enforce the rule mechanically rather than by
convention.

### S6. No benchmarks outside `keccak256`

Only `keccak256_bench_test.go` exists. The `golang-performance` skill
is the **primary** skill in the matrix for `sha-256`, `sha-3`,
`blake3`, `keccak-256`, and a secondary for several others. Without
benchmarks there is no regression detection for the hot paths the
matrix calls out. Add `b.Loop()` benchmarks for the remaining hashes,
both AEADs, and the sign/verify paths. Keep them as sub-benchmarks
(`b.Run`) keyed by input size so `benchstat` can diff them.

## Nits

### N1. `hex.DecodeString` errors are silently dropped in vector tests

Most RFC-vector tests use `seed, _ := hex.DecodeString(seedHex)`. A
typo in a vector hex silently yields an empty/short byte slice and
the assertion may pass for the wrong reason (e.g. comparing two empty
slices). `hkdf_test.go` already has a `mustHex(t, ...)` helper that
fatals on a decode error — adopt that pattern in every vector test.

### N2. Hand-rolled `itoa` / `wpItoa` / `fmtTCID` duplicated

`ed25519_test.go` and `secp256k1_test.go` each define their own
`itoa`/`wpItoa` (reimplementing `strconv.Itoa`) and near-identical
`fmtTCID`/`wpFmtTCID` formatters. `strconv.Itoa` is stdlib; the
hand-rolled versions add nothing and are duplicated. Replace with
`strconv.Itoa`. (Per `AGENTS.md` "no premature DRY" the duplication
itself is tolerable, but the hand-rolling is not justified.)

### N3. `TestVerify_HighS_Rejected` hand-rolls modular subtraction

`secp256k1_test.go` computes `n - s` with a manual byte-by-byte
borrow loop. The test already imports `math/big` (used in the
Wycheproof runner). Use `new(big.Int).Sub(n, sInt).Bytes()` — clearer,
less error-prone, and the curve order is already a `*big.Int` in the
Wycheproof section.

### N4. `TestBLAKE3_KnownVectors` has only two published digests

Only empty-string and `"abc"` are checked against published digests.
The `LargeInput` test asserts `Sum == SumBytes` and avalanche, but
not a known digest for a multi-chunk input. The BLAKE3 spec publishes
longer-input vectors; add at least one that crosses the 1024-byte
chunk boundary to exercise the tree path against a known answer.

### N5. `tamperLastByte` defined in `aesgcm_test.go`, used by `xchacha20_test.go`

Same package, so it compiles, but the helper's home file is
surprising for a reader of `xchacha20_test.go`. Move shared AEAD test
helpers to a `aead_test.go` (or a `helpers_test.go`) so they are
discoverable.

### N6. No `go.work` despite `AGENTS.md` stating "Local development via go.work"

Not a test failure, but `AGENTS.md` says local dev uses `go.work`
and the file is absent. Local `go test ./...` from the repo root
therefore does not span the three modules; CI works around this by
`working-directory` per matrix entry. Add a `go.work` listing all
three modules so the documented dev workflow actually works.

### N7. `auth/` and `chain/` are in the CI matrix but have no code

The CI matrix runs `go test -race` against `auth` and `chain`, which
are empty modules with no tests. This is harmless today but will
silently report "ok … (no test files)" and give false confidence
once code lands without tests. Consider gating the matrix on module
non-emptiness, or add a placeholder test that fails if the package
has source but no tests.

## Tier readiness (per `AGENTS.md` Testing Rules)

- **Tier 1 (Primitives)** — largely met. Known vectors (rule 10),
  round-trips (11), Wycheproof (12, partial — see M3), determinism
  (13) all present. Fuzzing and full Wycheproof coverage are the
  remaining gaps.
- **Tier 2 (Compositions)** — N/A yet. No envelope encryption, HPKE,
  or key recovery code exists. When it lands, rules 14–17 (composition
  round-trip, protocol-level vectors, error propagation,
  cross-primitive integration) apply.
- **Tier 3 (Identity, proofs, attestations)** — N/A. Packages
  declared (`identity`, `merkle`, `credential`, `attestation`,
  `signature`) but empty. Rules 18–22 will govern when implemented.
- **Tier 4 (Auth flows)** — N/A. `auth/` module exists but is empty.
  Rules 23–27 (full flow, HTTP handler, negative flows, contract
  tests, build-tag-gated provider integration) will govern.

## Recommended order of work

1. M1 (CI Go version) — unblock everything else.
2. M2 (cross-module isolation tests) — small, high value, pure rule
   compliance.
3. M3 (Wycheproof for AES-GCM, XChaCha20, X25519) — closes the
   matrix gap and the highest-value crypto coverage addition.
4. S1 (`t.Parallel`) — mechanical, large wall-time win.
5. S2/S3 (fuzz + examples) — small per-package additions.
6. S4 (testability of `GenerateKey` + direct `NewPrivateKey`/`NewPublicKey`
   success tests) — closes the reachable coverage gaps and surfaces
   the injectable-CSPRNG design question.
7. S5/S6, then nits.
