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

// pkceMinLen and pkceMaxLen are the [RFC 7636] §4.1 length bounds shared
// by code_verifier and code_challenge.
const (
	pkceMinLen = 43
	pkceMaxLen = 128
)

// isUnreserved reports whether c belongs to the unreserved character set
// per [RFC 3986] §2.3, which [RFC 7636] §4.1 adopts for code_verifier
// and code_challenge: ALPHA / DIGIT / "-" / "." / "_" / "~".
func isUnreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// validPKCEGrammar reports whether s conforms to the [RFC 7636] §4.1
// grammar shared by code_verifier and code_challenge:
//
//	code_verifier = code_challenge = 43*128unreserved
func validPKCEGrammar(s string) bool {
	if len(s) < pkceMinLen || len(s) > pkceMaxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isUnreserved(s[i]) {
			return false
		}
	}
	return true
}

// VerifyPKCE verifies a PKCE code verifier against the stored code
// challenge per [RFC 7636] §4.6.
//
// Grammar is enforced first ([RFC 7636] §4.1–4.2): the verifier and the
// challenge must each be 43–128 characters from the unreserved set, and
// the method must be "S256". Method "plain" is rejected — it sends the
// verifier in the clear over the token endpoint, defeating the purpose
// of PKCE.
//
// For method "S256": computes BASE64URL-NO-PAD(SHA256(verifier)) and
// compares it to the challenge using constant-time comparison.
//
// Returns nil on success, ErrInvalidPKCE on grammar violation, mismatch,
// or unsupported method.
func VerifyPKCE(verifier, challenge, method string) error {
	if method == MethodPlain {
		return ErrInvalidPKCE
	}
	if method != MethodS256 {
		return ErrInvalidPKCE
	}
	if !validPKCEGrammar(verifier) || !validPKCEGrammar(challenge) {
		return ErrInvalidPKCE
	}

	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])

	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return ErrInvalidPKCE
	}
	return nil
}
