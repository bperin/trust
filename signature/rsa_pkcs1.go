package signature

import (
	"crypto"

	"github.com/bperin/trust/crypto/rsa"
)

// init registers the RS256, RS384, and RS512 algorithms
// ([RFC 8017] §8.2 (PKCS1v1.5)) for RSA-PKCS1v1.5 signing and
// verification. RSA-PKCS1v1.5 hashes internally — the message is
// passed directly to the key's Sign/Verify methods. The bound hash
// determines the algorithm: SHA-256 for RS256, SHA-384 for RS384,
// SHA-512 for RS512. PKCS1v1.5 is deterministic: same key + message
// always produces the same signature.
func init() {
	register(AlgorithmRS256,
		func(key crypto.PrivateKey, msg []byte) ([]byte, error) {
			k, ok := key.(*rsa.PKCS1PrivateKey)
			if !ok {
				return nil, &ErrAlgMismatch{Expected: AlgorithmRS256, Got: algForPrivateKey(key)}
			}
			alg, err := rsaPKCS1AlgForHash(k.Public().Hash())
			if err != nil || alg != AlgorithmRS256 {
				return nil, &ErrAlgMismatch{Expected: AlgorithmRS256, Got: alg}
			}
			return k.Sign(msg)
		},
		func(key crypto.PublicKey, sig, msg []byte) (bool, error) {
			k, ok := key.(*rsa.PKCS1PublicKey)
			if !ok {
				return false, &ErrAlgMismatch{Expected: AlgorithmRS256, Got: algForPublicKey(key)}
			}
			alg, err := rsaPKCS1AlgForHash(k.Hash())
			if err != nil || alg != AlgorithmRS256 {
				return false, &ErrAlgMismatch{Expected: AlgorithmRS256, Got: alg}
			}
			return k.Verify(sig, msg), nil
		},
	)

	register(AlgorithmRS384,
		func(key crypto.PrivateKey, msg []byte) ([]byte, error) {
			k, ok := key.(*rsa.PKCS1PrivateKey)
			if !ok {
				return nil, &ErrAlgMismatch{Expected: AlgorithmRS384, Got: algForPrivateKey(key)}
			}
			alg, err := rsaPKCS1AlgForHash(k.Public().Hash())
			if err != nil || alg != AlgorithmRS384 {
				return nil, &ErrAlgMismatch{Expected: AlgorithmRS384, Got: alg}
			}
			return k.Sign(msg)
		},
		func(key crypto.PublicKey, sig, msg []byte) (bool, error) {
			k, ok := key.(*rsa.PKCS1PublicKey)
			if !ok {
				return false, &ErrAlgMismatch{Expected: AlgorithmRS384, Got: algForPublicKey(key)}
			}
			alg, err := rsaPKCS1AlgForHash(k.Hash())
			if err != nil || alg != AlgorithmRS384 {
				return false, &ErrAlgMismatch{Expected: AlgorithmRS384, Got: alg}
			}
			return k.Verify(sig, msg), nil
		},
	)

	register(AlgorithmRS512,
		func(key crypto.PrivateKey, msg []byte) ([]byte, error) {
			k, ok := key.(*rsa.PKCS1PrivateKey)
			if !ok {
				return nil, &ErrAlgMismatch{Expected: AlgorithmRS512, Got: algForPrivateKey(key)}
			}
			alg, err := rsaPKCS1AlgForHash(k.Public().Hash())
			if err != nil || alg != AlgorithmRS512 {
				return nil, &ErrAlgMismatch{Expected: AlgorithmRS512, Got: alg}
			}
			return k.Sign(msg)
		},
		func(key crypto.PublicKey, sig, msg []byte) (bool, error) {
			k, ok := key.(*rsa.PKCS1PublicKey)
			if !ok {
				return false, &ErrAlgMismatch{Expected: AlgorithmRS512, Got: algForPublicKey(key)}
			}
			alg, err := rsaPKCS1AlgForHash(k.Hash())
			if err != nil || alg != AlgorithmRS512 {
				return false, &ErrAlgMismatch{Expected: AlgorithmRS512, Got: alg}
			}
			return k.Verify(sig, msg), nil
		},
	)
}
