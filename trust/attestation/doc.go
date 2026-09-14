// Package attestation implements Entity Attestation Tokens (EAT) as CWTs
// signed with COSE Sign1 per [RFC 8392] and [RFC 9052].
//
// The package has two layers:
//
//   - eat.go holds the generic Attestation struct — a signed claim
//     envelope with a canonical-hash identity. SignAttestation and
//     VerifyAttestation operate on this type.
//   - eat_cbor.go holds the EAT/COSE standard-format path: CWT
//     claim constants, Issue and Verify for [RFC 9052] COSE_Sign1
//     tokens, and claim/time validation.
//
// EAT claims use the CWT integer labels defined in [RFC 8392] §3.1.1 (iss=1,
// sub=2, aud=3, exp=4, nbf=5, iat=6, cti=7) plus a nonce label (10). The
// token is a COSE_Sign1 object; the payload is a canonical CBOR map of claims.
package attestation
