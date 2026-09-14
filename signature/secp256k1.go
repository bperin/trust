package signature

import (
	"crypto"
	"crypto/sha256"

	"github.com/bperin/trust/crypto/secp256k1"
)

// init registers the ES256K algorithm ([SEC 2 v2]; [RFC 6979]; [EIP-2])
// for secp256k1 signing and verification. secp256k1 Sign/Verify
// operate on a 32-byte pre-computed hash; this closure SHA-256
// pre-hashes the message before passing it to the key. The dcrd
// library produces low-s canonical signatures per [EIP-2]
// automatically.
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
