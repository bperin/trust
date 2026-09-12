package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// MethodS256 is the PKCE code challenge method "S256" per [RFC 7636] §4.2.
// The challenge is BASE64URL-NO-PAD(SHA256(ASCII(code_verifier))).
const MethodS256 = "S256"

// MethodPlain is the PKCE code challenge method "plain" per [RFC 7636] §4.2.
// The challenge equals the verifier. This method is rejected — S256 is
// required for all PKCE exchanges.
const MethodPlain = "plain"

// VerifyPKCE verifies a PKCE code verifier against the stored code
// challenge per [RFC 7636] §4.6.
//
// For method "S256": computes BASE64URL-NO-PAD(SHA256(verifier)) and
// compares it to the challenge using constant-time comparison.
//
// For method "plain": returns ErrInvalidPKCE — S256 is required.
// Plain method is rejected because it sends the verifier in the clear
// over the token endpoint, defeating the purpose of PKCE.
//
// Returns nil on success, ErrInvalidPKCE on mismatch or unsupported method.
func VerifyPKCE(verifier, challenge, method string) error {
	if method == MethodPlain {
		return ErrInvalidPKCE
	}
	if method != MethodS256 {
		return ErrInvalidPKCE
	}
	if verifier == "" || challenge == "" {
		return ErrInvalidPKCE
	}

	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])

	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return ErrInvalidPKCE
	}
	return nil
}
