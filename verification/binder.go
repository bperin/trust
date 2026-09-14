package verification

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/identity/did"
)

// KeyBinder extracts the public key for a key ID from a DID document.
// Consumer-side, single method.
type KeyBinder interface {
	// Bind extracts the public key for keyID from doc.
	Bind(keyID string, doc *did.Document) (crypto.PublicKey, error)
}

// DocumentKeyBinder is the default KeyBinder: it extracts Ed25519
// public keys from a DID document's verification methods, reading
// PublicKeyMultibase (base58btc "z" or base64url-nopad "u") or
// PublicKeyJWK (kty OKP, crv Ed25519).
type DocumentKeyBinder struct{}

// Bind implements KeyBinder for standard Ed25519 verification methods.
func (DocumentKeyBinder) Bind(keyID string, doc *did.Document) (crypto.PublicKey, error) {
	if doc == nil {
		return nil, fmt.Errorf("verification: bind %q: nil DID document", keyID)
	}
	for _, m := range doc.VerificationMethod {
		if !methodMatches(m, doc.ID, keyID) {
			continue
		}
		if m.PublicKeyMultibase != "" {
			key, err := parseMultibaseEd25519(m.PublicKeyMultibase)
			if err != nil {
				return nil, fmt.Errorf("verification: bind %q: %w", keyID, err)
			}
			return key, nil
		}
		if len(m.PublicKeyJWK) > 0 {
			key, err := parseJWKEd25519(m.PublicKeyJWK)
			if err != nil {
				return nil, fmt.Errorf("verification: bind %q: %w", keyID, err)
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("verification: bind %q: key not found in DID document", keyID)
}

// methodMatches reports whether a verification method's ID matches
// keyID exactly or by fragment.
func methodMatches(m did.Method, docID, keyID string) bool {
	return m.ID == keyID || m.ID == docID+"#"+keyID
}

// parseMultibaseEd25519 decodes a multibase-encoded Ed25519 public key.
func parseMultibaseEd25519(s string) (crypto.PublicKey, error) {
	if len(s) < 2 {
		return nil, errors.New("verification: empty multibase value")
	}
	var raw []byte
	switch s[0] {
	case 'z':
		v, err := decodeBase58BTC(s[1:])
		if err != nil {
			return nil, fmt.Errorf("verification: multibase base58btc: %w", err)
		}
		raw = v
	case 'u':
		v, err := base64.RawURLEncoding.DecodeString(s[1:])
		if err != nil {
			return nil, fmt.Errorf("verification: multibase base64url: %w", err)
		}
		raw = v
	default:
		return nil, fmt.Errorf("verification: unsupported multibase prefix %q", s[0])
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("verification: multibase key is %d bytes, want 32", len(raw))
	}
	return trustEd25519Pub(raw)
}

// trustEd25519Pub wraps 32 raw bytes as a trust Ed25519 public key.
func trustEd25519Pub(raw []byte) (crypto.PublicKey, error) {
	return ed25519.NewPublicKey(raw)
}

// parseJWKEd25519 extracts an Ed25519 public key from an OKP JWK.
func parseJWKEd25519(jwk map[string]any) (crypto.PublicKey, error) {
	if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
		return nil, errors.New("verification: JWK is not an Ed25519 OKP key")
	}
	x, ok := jwk["x"].(string)
	if !ok || x == "" {
		return nil, errors.New("verification: JWK missing x coordinate")
	}
	raw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("verification: JWK x decode: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("verification: JWK x is %d bytes, want 32", len(raw))
	}
	return trustEd25519Pub(raw)
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// decodeBase58BTC decodes a base58btc string.
func decodeBase58BTC(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty input")
	}
	out := []byte{}
	for _, c := range []byte(s) {
		idx := strings.IndexByte(base58Alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", c)
		}
		carry := idx
		for j := len(out) - 1; j >= 0; j-- {
			carry += 58 * int(out[j])
			out[j] = byte(carry % 256)
			carry /= 256
		}
		for carry > 0 {
			out = append([]byte{byte(carry % 256)}, out...)
			carry /= 256
		}
	}
	// Leading '1's encode leading zero bytes.
	for i := 0; i < len(s) && s[i] == '1'; i++ {
		out = append([]byte{0}, out...)
	}
	return out, nil
}
