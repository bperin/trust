package signature

import (
	"crypto"

	"github.com/bperin/trust/crypto/ed25519"
)

// init registers the EdDSA algorithm ([RFC 8037]; [FIPS 186-5]) for
// Ed25519 signing and verification. Ed25519 hashes internally per
// [RFC 8032] §2.6 — no pre-hashing is applied. ed25519.PrivateKey.Sign
// returns []byte only (no error), so the sign closure wraps with nil.
func init() {
	register(AlgorithmEdDSA,
		func(key crypto.PrivateKey, msg []byte) ([]byte, error) {
			k, ok := key.(*ed25519.PrivateKey)
			if !ok {
				return nil, &ErrAlgMismatch{Expected: AlgorithmEdDSA, Got: algForPrivateKey(key)}
			}
			return k.Sign(msg), nil
		},
		func(key crypto.PublicKey, sig, msg []byte) (bool, error) {
			k, ok := key.(*ed25519.PublicKey)
			if !ok {
				return false, &ErrAlgMismatch{Expected: AlgorithmEdDSA, Got: algForPublicKey(key)}
			}
			return k.Verify(sig, msg), nil
		},
	)
}
