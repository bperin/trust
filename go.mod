// Module github.com/bperin/trust — Go primitives and protocol adapters for
// cryptographic identity, authorization, delegation, attestations, proofs,
// and blockchain commitments.
//
// Single module containing four capability areas:
//   - trust/   — crypto core (hashes, signatures, AEAD, keys, merkle, identity)
//   - auth/    — OIDC, OAuth2, WebAuthn, sessions, claims
//   - chain/   — EVM, Ethereum, wallet, EIP-712, RPC
//   - kms/     — remote-KMS signing core for secp256k1
//
// Dependency footprint: standard wire formats delegate to vetted Go libraries
// rather than hand-rolled reimplementations. Direct dependencies are
// decred/dcrd (secp256k1), fxamacker/cbor (CBOR/EAT), zeebo/blake3 (BLAKE3),
// golang.org/x/crypto (HKDF, argon2, and related primitives), circl (HPKE),
// jwx (JWK/JWS/COSE), and veraison/go-cose (COSE Sign1).
module github.com/bperin/trust

go 1.27.1

require (
	github.com/cloudflare/circl v1.6.5
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/fxamacker/cbor/v2 v2.9.3
	github.com/lestrrat-go/jwx/v3 v3.3.0
	github.com/veraison/go-cose v1.3.0
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.57.0
)

require (
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
