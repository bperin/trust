package signature

import (
	"crypto"

	"github.com/bperin/trust/crypto/ed25519"
)

// init registers the EdDSA algorithm for Ed25519 signing and
// verification [RFC 8032].
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
