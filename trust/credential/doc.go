// Package credential implements [W3C VC-DATA-MODEL] Verifiable Credentials
// issue/verify/present with JWT proof encoding per [VC-JWT].
//
// The package has two layers:
//
//   - credential.go holds the custom VersionedClaim envelope — the
//     stable cryptographic wrapper around a domain payload, consumed
//     by the attestation layer. CanonicalHash and Validate operate on
//     this type.
//   - vc.go holds the VC/JWT standard-format path: Credential,
//     Presentation, Issue, Verify, Present, and VerifyPresentation
//     for [W3C VC-DATA-MODEL] and [VC-JWT].
//
// Credentials and presentations are signed as JWS compact tokens using the
// trust key wrapper; the credential or presentation object is embedded in the
// "vc" or "vp" JWT claim. Verification checks the JWS signature and standard
// JWT claims (iss, sub, aud, exp, nbf, iat) against caller-supplied pins.
package credential
