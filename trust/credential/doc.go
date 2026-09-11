// Package credential implements [W3C VC-DATA-MODEL] Verifiable Credentials
// issue/verify/present with JWT proof encoding per [VC-JWT].
//
// Credentials and presentations are signed as JWS compact tokens using the
// trust key wrappers; the credential or presentation object is embedded in the
// "vc" or "vp" JWT claim. Verification checks the JWS signature and standard
// JWT claims (iss, sub, aud, exp, nbf, iat) against caller-supplied pins.
package credential
