# SPEC-002: auth — Authentication & Authorization

<!-- Template hierarchy: SPEC-NNN → plans/PLAN-NNN.md → tasks/TASK-NNN.md -->
<!-- This SPEC describes WHAT and WHY. The Architect determines HOW in plans/PLAN-002.md. -->

## Supersedes

- Supersedes: the auth portion of the original combined SPEC-001
- Reason: split per architecture guidance — establish trust core first (SPEC-001), then
  auth, then chain. The original combined spec also had architectural errors: SIWE in
  `auth` required EVM primitives that were only in `chain`, creating a dependency-rule
  violation. SPEC-001 now provides secp256k1 recovery + Keccak-256 in `trust`, so `auth`
  can implement SIWE by importing `trust` only.
- Superseded by: none

## What

An authentication and authorization module that answers "who is this user or service, and
what are they authorized to do?" It supports OAuth2, OpenID Connect, WebAuthn/passkeys,
SIWE (Sign-In with Ethereum), JWT-based sessions, and password-based login. It maps every
authenticated identity into a `trust.Identity` so that downstream systems (attestations,
agent signing, blockchain anchoring) operate on a unified identity type. It consolidates
the duplicated HS256 JWT issuer, bcrypt password hashing, random token generation, and
OAuth2/PKCE/refresh-rotation code currently split across `ghost-protocol` and `trakt2`.

## Why

- **Eliminate duplicated auth code.** `ghost-protocol` and `trakt2` each ship a
  near-identical hand-rolled HS256 `TokenIssuer` + `Claims` (`internal/security/jwt.go`).
  `trakt2` additionally ships `BcryptPasswordVerifier`, `RandomTokenGenerator`
  (URL-safe random + SHA-256 storage hash), `JWTAccessTokenIssuer` adapter, and a full
  OAuth2 auth-code + PKCE + refresh-token rotation/reuse-detection service
  (`internal/auth/service.go`). `ghost-protocol` ships a SIWE nonce store, SIWE
  verification service, and Bearer JWT middleware. Every new project re-implements these
  with drifting claim structures and error conventions.
- **Unify identity mapping.** OIDC subjects, SIWE wallet addresses, and WebAuthn
  credentials all map into `trust.Identity` so attestation and agent-signing systems
  don't need to know which auth method was used.
- **Separate authentication from attestation.** Successfully authenticating through OIDC
  or SIWE does not itself constitute proof of authority to issue an attestation. Auth
  establishes who you are; `trust` establishes what you can cryptographically prove.
- **Support asymmetric JWT signing.** The original code is HS256-only (shared secret).
  OIDC ID tokens are normally RS256/ES256/EdDSA verified from JWKS. The consolidated JWT
  issuer must support asymmetric algorithms alongside HS256, with `alg: none` rejection
  and per-key algorithm whitelisting.

## Desired Behavior

### JWT Issuance & Validation

1. An application can issue and validate JWT access tokens and refresh tokens using HS256
   (shared secret, single-service) or asymmetric algorithms (RS256, ES256, EdDSA) with
   JWKS-based key resolution for validation.
2. The JWT validator rejects `alg: none`, whitelists algorithms per key, matches `kty` to
   `alg`, and validates `typ`/`cty` headers.
3. The JWT issuer supports extensible claims — application-specific fields (organization
   ID, plan tier, billing status) are carried without the core knowing what they mean.
4. JWT signing and verification primitives (HMAC, RSA, ECDSA, Ed25519) come from `trust`,
  not re-implemented in `auth`.

### Password Authentication

5. An application can hash and verify first-party passwords with bcrypt (consolidating
  `trakt2`'s `BcryptPasswordVerifier`).

### OAuth2

6. An application can run an OAuth2 authorization-code flow with PKCE (S256 challenge
   method), including single-use authorization code issuance, redemption, and rotation
   (consolidating `trakt2`'s `auth/service.go`).
7. Refresh tokens are rotated on each use, with reuse detection: if a refresh token is
   used twice, the entire token family is revoked (consolidating `trakt2`'s
  reuse-detection logic).
8. OAuth2 redirect flows use a cryptographically random `state` parameter to
   mitigate CSRF. The state is single-use, bound to the session, and validated
   on callback before any token exchange.

### OpenID Connect

8. An application can perform OIDC discovery, validate ID tokens from any compliant
   provider via JWKS, and extract userinfo claims, mapping the OIDC subject into a
  `trust.Identity`.

### WebAuthn / Passkeys

9. An application can register and authenticate users via WebAuthn / FIDO2 passkeys
   without a password.

### SIWE (Sign-In with Ethereum)

10. An application can authenticate a blockchain wallet via SIWE (EIP-4361): generate
    nonces, verify the EIP-191 signature, and issue a JWT — mapping the verified wallet
    address into a `trust.Identity` / `did:pkh`.
11. SIWE verification uses `trust`'s secp256k1 public-key recovery, Keccak-256, and EVM
    address derivation — never importing `chain`.
12. Nonces are single-use with a TTL (consolidating `ghost-protocol`'s nonce store in
    `wallet/repository.go`).

### Session Management

13. An application can manage server-side sessions with cookie management and revocation.

### Claims & Authorization

14. An application can extract, validate, and enforce scopes, roles, and arbitrary claims
    from JWT or OIDC tokens (consolidating `trakt2`'s role hierarchy in
    `infra/auth/roles.go` and `ghost-protocol`'s Bearer middleware).

### Token Generation

15. An application can generate URL-safe random tokens with SHA-256 storage hashes for
    refresh tokens, auth codes, and session IDs (consolidating `trakt2`'s
    `RandomTokenGenerator`).
16. An application can generate hex-encoded nonces and numeric confirmation codes for
    SIWE and email verification (consolidating `ghost-protocol`'s `wallet/util.go`
    `randomHex` and `trakt2`'s `generateNumericCode`).

### Auth ≠ Attestation

17. Authentication remains separate from cryptographic attestation. No auth flow grants
    signing authority — that is established separately through `trust` key possession.

## Scope

### In Scope

- `auth` module with packages: `jwt`, `password`, `oauth`, `oidc`, `webauthn`, `siwe`,
  `session`, `claims`.
- Consolidated HS256 + asymmetric JWT issuer/validator with JWKS support.
- bcrypt password hashing.
- OAuth2 auth-code flow with PKCE, refresh-token rotation and reuse detection.
- OIDC discovery, ID token validation, userinfo.
- WebAuthn registration and login.
- SIWE (EIP-4361) nonce generation, signature verification, JWT issuance.
- Server-side session store with cookie management and revocation.
- Claims extraction, scope/role enforcement, arbitrary claim validation.
- URL-safe token generation, hex nonce generation, numeric confirmation code generation.
- Mapping all authenticated identities into `trust.Identity`.

### Out of Scope

- Cryptographic primitives (SPEC-001, `trust` — signing, hashing, key derivation, AEAD).
- Attestation issuance or verification (SPEC-001, `trust`).
- Merkle trees or proofs (SPEC-001, `trust`).
- EIP-712 typed-data signing (SPEC-003, `chain`).
- EVM transaction construction or blockchain anchoring (SPEC-003, `chain`).
- RPC provider adapters (SPEC-003, `chain`).
- Application-specific user databases, billing logic, Stripe integration, or email
  sending (stays in consuming applications).
- Account-recovery flows (password reset, email confirmation) — these are
  application-specific orchestration on top of `auth` primitives, not part of the
  reusable module. The module provides the token-generation and password-hashing
  primitives; the consuming app builds the lifecycle flows.
- mTLS / service workload authentication (future spec).
- Agent protocol implementations (A2A, etc. — live above `auth`).

## Constraints

- `auth` may import `trust` only. `auth` must never import `chain`.
- JWT signing and verification must delegate to `trust` primitives (HMAC-SHA256, RSA,
  ECDSA, Ed25519) — no re-implementation of crypto in `auth`.
- SIWE signature verification must use `trust`'s secp256k1 recovery + Keccak-256 —
  never import `chain`.
- No reflection-based runtime DI. Explicit constructor composition.
- No interface inflation: expose concrete structs; define interfaces near the consumer.
- Private keys and JWT secrets must never be logged or exposed.
- All externally supplied JWTs, OIDC tokens, SIWE messages, and WebAuthn assertions are
  untrusted input and must be validated before use. Verification failures fail closed.
- `alg: none` is always rejected. Algorithm whitelisting is per-key.
- Refresh-token reuse must trigger family revocation, not just token revocation.
- **Godoc standard citations:** every exported declaration must cite the governing
  standard in its Godoc comment (RFC number, EIP number, W3C/OIDF spec name). Format:
  `// IssueAccessToken implements [RFC 7519] section 4.1.` followed by the plain-language
  rationale. If a function implements part of an OAuth/OIDC flow, cite the specific
  RFC section and the step it performs.

### Dependency Matrix

| Capability | Dependency | Rationale |
|------------|------------|-----------|
| JWT (asymmetric alg, JWKS, alg whitelisting) | `github.com/golang-jwt/jwt/v5` | Vetted JWT library — handles RS256/ES256/EdDSA, JWKS key resolution, `alg: none` rejection, claim validation per RFC 8725 BCP. Don't hand-roll asymmetric JWT. |
| SIWE (EIP-4361) | `github.com/signinwithethereum/siwe-go` | EIP-4361 message parsing |
| OIDC | `github.com/coreos/go-oidc/v3` | Discovery, ID token validation |
| WebAuthn | `github.com/go-webauthn/webauthn` | Passkey registration/login |
| OAuth2 | `golang.org/x/oauth2` | OAuth2 client — gold standard per go-security-expert |
| bcrypt | `golang.org/x/crypto/bcrypt` | Password hashing |
| JWT signing/verification primitives | `trust` (SPEC-001) | HMAC-SHA256, RSA, ECDSA, Ed25519 — all crypto goes through trust |

## Success Criteria

1. `go build ./...` succeeds from `auth/`.
2. `go vet ./...` is clean from `auth/`.
3. `go test ./...` passes from `auth/` with no skipped tests.
4. The consolidated JWT issuer issues an HS256 token and validates it, with claims
   matching the structure of both `ghost-protocol/internal/security/jwt.go` and
   `trakt2/internal/infra/security/jwt.go` (sub, scopes, roles, iss, aud, exp, nbf, iat,
   jti, plus extensible custom claims). A token with `alg: none` is rejected. A token
   signed with HS256 but presented to an RS256-only validator is rejected.
5. The JWT issuer issues an ES256 token using a `trust` ECDSA P-256 key and validates it
   via JWKS key resolution. A tampered payload causes validation to fail.
6. bcrypt hashes a known password and verification succeeds. A wrong password fails.
   (Matches `trakt2`'s `BcryptPasswordVerifier` behavior.)
7. OAuth2 auth-code flow: an authorization code is issued with a PKCE S256 challenge,
   redeemed with the correct verifier, and rejected with a wrong verifier. A consumed
   code cannot be redeemed again. The `state` parameter is cryptographically random,
   single-use, and a callback with a wrong or missing `state` is rejected.
8. Refresh-token rotation: a refresh token is rotated on use, the old token is invalid
   after rotation, and reuse of the old token revokes the entire family.
9. SIWE: a known EIP-4361 message + signature is verified, the wallet address is
   recovered using `trust`'s secp256k1 recovery, and a JWT is issued. A nonce is
   single-use — a second verification with the same nonce fails. (No `chain` import in
   the `siwe` package — verifiable by `grep -r 'chain' auth/siwe/` returning nothing.)
10. URL-safe token generation produces a token of the expected length, and its SHA-256
    storage hash matches `base64url(sha256(token))`. (Matches `trakt2`'s
    `RandomTokenGenerator` behavior.)
11. Numeric confirmation code generation produces an N-digit string of only digits
    `0-9`. Two consecutive calls produce different codes.
12. Claims extraction from a JWT returns the correct scopes and roles. A token with
    insufficient scope for a required action is rejected by the enforcement middleware.
    A token missing `exp`, `iat`, `iss`, or `aud` is rejected. An expired token is
    rejected. A token with a future `iat` (clock skew) is rejected.
13. No `chain` import exists anywhere in `auth/` (verifiable by
    `grep -r 'github.com/brianperin/chain' auth/` returning nothing).
14. No crypto re-implementation: no direct use of `crypto/hmac`, `crypto/rsa`,
    `crypto/ecdsa`, or `crypto/ed25519` in `auth/` — all signing/verification goes
    through `trust` (verifiable by grep). No use of `math/rand` anywhere in `auth/`
    (verifiable by grep — only `crypto/rand` or `trust`'s random primitive).
15. `govulncheck ./...` reports no known vulnerabilities in `auth/` dependencies.

## Standards & References

### JWT / JWS / JWK

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| JWT structure | RFC 7519 (JSON Web Token) | The standard compact token format. Every OIDC provider, every API gateway, every modern auth stack speaks JWT. |
| JWS (signing) | RFC 7515 (JSON Web Signature) | Defines the `header.payload.signature` structure and detached signatures. |
| JWK / JWKS | RFC 7517 (JSON Web Key) | Standard JSON key format. OIDC providers publish JWKS endpoints; we fetch keys from there for asymmetric JWT validation. |
| JWT algorithms | RFC 7518 (JSON Web Algorithms) | The algorithm registry — HS256, RS256, ES256, EdDSA. We whitelist per key. |
| JWT best practices | RFC 8725 (JWT BCP) | The authoritative security guidance: reject `alg: none`, bind audience, rotate keys, enforce `exp`/`nbf`. We follow all of it. |
| `alg: none` rejection | RFC 8725 §3.1 | The classic JWT vulnerability — an attacker sets `alg: none` and the validator skips signature checking. Always reject. |

### Password Hashing

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| bcrypt | Provos & Mazières, "A Future-Adaptable Password Scheme" (USENIX 1999) | Adaptive cost — slows down as hardware improves. The standard for first-party password hashing. Argon2id is the NIST-recommended alternative (SP 800-63B) but bcrypt is battle-tested and simpler. |

### OAuth2

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| OAuth2 framework | RFC 6749 (The OAuth 2.0 Authorization Framework) | The standard delegated-authorization framework. Every major provider (Google, GitHub, Microsoft) implements it. |
| Authorization code flow | RFC 6749 §4.1 | The most secure OAuth2 flow for server-side apps. The code is short-lived and single-use. |
| PKCE | RFC 7636 (Proof Key for Code Exchange) | Prevents authorization-code interception attacks. Mandatory for public clients; we require it for all flows. |
| OAuth2 state parameter | RFC 6749 §10.12 (CSRF protection) | Cryptographically random `state` binds the redirect to the user's session. Without it, an attacker can inject their own authorization code. Single-use, validated on callback. |
| Token revocation | RFC 7009 (OAuth 2.0 Token Revocation) | Standard endpoint for revoking access and refresh tokens. |
| Token introspection | RFC 7662 (OAuth 2.0 Token Introspection) | Standard endpoint for checking token validity server-side. |
| OAuth2 BCP | RFC 9700 (OAuth 2.0 Security Best Current Practice) | Replaces RFC 6819. Mandates PKCE for all clients, recommends exact redirect URI matching, discourages implicit flow. |

### OpenID Connect

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| OIDC Core | OpenID Connect Core 1.0 (OIDF) | Identity layer on top of OAuth2. Gives us `id_token`, userinfo, and standardized claims (sub, email, name). |
| OIDC Discovery | OpenID Connect Discovery 1.0 (OIDF) | Lets us auto-configure a provider from a single URL (`/.well-known/openid-configuration`). No hard-coded endpoints. |
| OIDC JWKS | OpenID Connect Core 1.0 §4.3; RFC 7517 §5 | Provider publishes signing keys at a JWKS endpoint. We fetch and cache them for ID token validation. |

### WebAuthn

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| WebAuthn | W3C Web Authentication Level 2 | Browser API for passkey registration and login. Replaces passwords with device-bound public keys. |
| CTAP | FIDO2 CTAP 2.1 | The client-to-authenticator protocol. WebAuthn is the browser side; CTAP is the device side. Together they're "passkeys." |

### SIWE

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| SIWE | EIP-4361 (Sign-In with Ethereum) | Standard for authenticating with an Ethereum wallet. The user signs a message; we verify the signature and recover the address. No password, no email, no third-party IdP. |
| EIP-191 personal_sign prefix | EIP-191 (Signed Data Standard) | Defines the `\x19Ethereum Signed Message:\n` prefix that prevents a signed message from being replayed as a transaction. |

### Sessions

| Capability | Standard | Why we use it |
|------------|----------|---------------|
| Session cookies | RFC 6265bis (HTTP State Management Mechanism) | The standard for HTTP cookies. `Secure`, `HttpOnly`, `SameSite` flags prevent XSS and CSRF token theft. |

### Military-Grade & National Security References

These standards govern authentication assurance and authenticator management in
US federal and national security systems. The Godoc comments must cite them where
applicable so consumers building federal/NSS systems know which AAL level a flow
satisfies and what controls are enforced.

| Capability | Standard | Applicability |
|------------|----------|---------------|
| Password authentication | SP 800-63B Rev3 §5 (Digital Identity Guidelines — Authentication) | NIST removed verifier-side complexity rules; password strength is length-based (min 8 chars, 64+ recommended). bcrypt meets the verifier requirements. Cite AAL1 (single-factor). |
| JWT / OIDC token auth | SP 800-63B Rev3 §6 | OIDC + PKCE + refresh rotation can satisfy AAL2 (multi-factor) when combined with a second factor. JWT alone is AAL1. Cite the AAL level in Godoc. |
| WebAuthn / passkeys | SP 800-63B Rev3 §6.2; FIPS 140-3 | WebAuthn with a hardware authenticator satisfies AAL3 (hardware-bound, phishing-resistant). The highest federal assurance level. Cite AAL3. |
| SIWE (wallet auth) | Not in SP 800-63B | SIWE is not a NIST-recognized authenticator. It's a Web3-native auth method. No AAL citation. Note the gap for federal consumers. |
| Multi-factor authentication | SP 800-53 Rev5 IA-2(1) | Federal control requiring MFA for privileged accounts. OIDC + WebAuthn or OIDC + TOTP satisfies this. Cite on MFA-enforcing functions. |
| Authenticator management | SP 800-53 Rev5 IA-5 | Federal control for authenticator (password, token, key) lifecycle — issuance, rotation, revocation. Our refresh-token rotation and session revocation implement IA-5 controls. Cite on revocation functions. |
| Session timeout | DoD STIG (Application Security STIG, session management) | DoD STIG requires session idle timeout (typically 15 min for unclassified, 10 min for TS). Our session TTL is configurable. Cite the STIG control on session-config functions. |
| Cryptographic token protection | SP 800-53 Rev5 SC-13 | Federal control requiring FIPS-validated crypto for token signing. HS256 via Go stdlib HMAC is not FIPS-validated by default; ES256/EdDSA via BoringCrypto is. Note in Godoc. |
| CUI protection | SP 800-171 (Protecting Controlled Unclassified Information) | If auth tokens protect CUI, the crypto must be FIPS-validated. Cite on JWT issuer when targeting CUI environments. |

## Linked Plan

- Plan: `plans/PLAN-002.md` (created by Architect)
- Tasks: listed in the plan under Workstreams

## Source Material

- `ghost-protocol/backend/internal/security/jwt.go` — HS256 TokenIssuer + Claims
- `trakt2/trakt2-api/internal/infra/security/jwt.go` — HS256 TokenIssuer + Claims
  (diverged: added OrganizationID, PlanTier, BillingStatus)
- `trakt2/trakt2-api/internal/infra/security/oauth.go` — BcryptPasswordVerifier,
  RandomTokenGenerator, JWTAccessTokenIssuer adapter
- `trakt2/trakt2-api/internal/auth/service.go` — OAuth2 auth-code + PKCE, refresh-token
  rotation/reuse-detection, password reset, signup confirmation
- `trakt2/trakt2-api/internal/auth/model.go` — RefreshSession, AuthCode, SignupConfirmation,
  ResetToken, User domain models
- `trakt2/trakt2-api/internal/auth/handler.go` — HTTP handlers for auth flows
- `trakt2/trakt2-api/internal/auth/routes.go` — Route registration
- `trakt2/trakt2-api/internal/infra/auth/middleware.go` — Bearer JWT validation + role/org
  enforcement
- `trakt2/trakt2-api/internal/infra/auth/context.go` — Context keys for auth values
- `trakt2/trakt2-api/internal/infra/auth/roles.go` — Role hierarchy, HasMinimumRole
- `trakt2/trakt2-api/internal/infra/auth/billing_middleware.go` — Billing status enforcement
- `trakt2/trakt2-api/internal/infra/auth/plan_middleware.go` — Plan tier enforcement
- `ghost-protocol/backend/internal/wallet/service.go` — SIWE nonce generation, signature
  verification, JWT issuance, investor whitelist
- `ghost-protocol/backend/internal/wallet/repository.go` — Single-use SIWE nonce store
  with TTL (memory + Postgres)
- `ghost-protocol/backend/internal/wallet/handler.go` — SIWE HTTP routes
- `ghost-protocol/backend/internal/wallet/util.go` — randomHex nonce generator
- `ghost-protocol/backend/internal/infra/http/middleware.go` — Bearer JWT middleware
- `Go Trust & Security Platform — Architecture Specification.md` (root)
- `spec/00-thesis.md` (root)
