package verification

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/identity/did"
)

// KeyBinder extracts the public key for a key ID from a DID document.
type KeyBinder interface {
	// Bind extracts the public key for keyID from doc.
	Bind(keyID string, doc *did.Document) (crypto.PublicKey, error)
}

// DocumentKeyBinder is the default KeyBinder: it binds a DID verification
// method declaring any registered signature.Algorithm.
type DocumentKeyBinder struct{}

// Bind implements KeyBinder for verification methods of any registered algorithm.
func (DocumentKeyBinder) Bind(keyID string, doc *did.Document) (crypto.PublicKey, error) {
	if doc == nil {
		return nil, fmt.Errorf("verification: bind %q: nil DID document", keyID)
	}
	for _, m := range doc.VerificationMethod {
		if !methodMatches(m, doc.ID, keyID) || !hasKeyMaterial(m) {
			continue
		}
		key, err := bindMethod(m)
		if err != nil {
			return nil, fmt.Errorf("verification: bind %q: %w", keyID, err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("verification: bind %q: key not found in DID document", keyID)
}

// methodMatches reports whether m matches keyID exactly or by fragment.
func methodMatches(m did.Method, docID, keyID string) bool {
	return m.ID == keyID || m.ID == docID+"#"+keyID
}

// hasKeyMaterial reports whether m carries bindable public key material.
func hasKeyMaterial(m did.Method) bool {
	return m.PublicKeyMultibase != "" || len(m.PublicKeyJWK) > 0
}

// trustEd25519Pub wraps 32 raw bytes as a trust Ed25519 public key.
func trustEd25519Pub(raw []byte) (crypto.PublicKey, error) {
	return ed25519.NewPublicKey(raw)
}

// decodeMultibase decodes a multibase byte string for the base58btc,
// base64url, and base16 prefixes.
func decodeMultibase(s string) ([]byte, error) {
	if len(s) < 2 {
		return nil, errors.New("verification: empty multibase value")
	}
	switch s[0] {
	case 'z':
		v, err := decodeBase58BTC(s[1:])
		if err != nil {
			return nil, fmt.Errorf("verification: multibase base58btc: %w", err)
		}
		return v, nil
	case 'u':
		v, err := base64.RawURLEncoding.DecodeString(s[1:])
		if err != nil {
			return nil, fmt.Errorf("verification: multibase base64url: %w", err)
		}
		return v, nil
	case 'f', 'F':
		v, err := hex.DecodeString(s[1:])
		if err != nil {
			return nil, fmt.Errorf("verification: multibase base16: %w", err)
		}
		return v, nil
	default:
		return nil, fmt.Errorf("verification: unsupported multibase prefix %q", s[0])
	}
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
