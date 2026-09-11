// Package attestation implements Entity Attestation Tokens (EAT) as CWTs
// signed with COSE Sign1 per [RFC 8392] and [RFC 9052].
//
// EAT claims use the CWT integer labels defined in [RFC 8392] §3.1.1 (iss=1,
// sub=2, aud=3, exp=4, nbf=5, iat=6, cti=7) plus a nonce label (10). The
// token is a COSE_Sign1 object; the payload is a canonical CBOR map of claims.
package attestation
