package signature

import (
	"crypto"
	"crypto/sha256"

	"github.com/bperin/trust/crypto/secp256k1"
)

// init registers the ES256K algorithm for secp256k1 signing and
// verification [RFC 8812]. The message is SHA-256 pre-hashed before
// being passed to the key.
func init() {
	register(AlgorithmES256K,
		func(key crypto.PrivateKey, msg []byte) ([]byte, error) {
			k, ok := key.(*secp256k1.PrivateKey)
			if !ok {
				return nil, &ErrAlgMismatch{Expected: AlgorithmES256K, Got: algForPrivateKey(key)}
			}
			digest := sha256.Sum256(msg)
			return k.Sign(digest[:])
		},
		func(key crypto.PublicKey, sig, msg []byte) (bool, error) {
			k, ok := key.(*secp256k1.PublicKey)
			if !ok {
				return false, &ErrAlgMismatch{Expected: AlgorithmES256K, Got: algForPublicKey(key)}
			}
			digest := sha256.Sum256(msg)
			return k.Verify(sig, digest[:]), nil
		},
	)
}
