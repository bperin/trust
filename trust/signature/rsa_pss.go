package signature

import (
	"crypto"

	"github.com/bperin/trust/crypto/rsa"
)

// init registers the PS256, PS384, and PS512 algorithms
// ([RFC 8017] (PKCS#1 v2.2, PSS)) for RSA-PSS signing and
// verification. RSA-PSS hashes internally — the message is passed
// directly to the key's Sign/Verify methods. The bound hash
// determines the algorithm: SHA-256 for PS256, SHA-384 for PS384,
// SHA-512 for PS512. PSS salt length is fixed to the hash output
// length by the key implementation.
func init() {
	register(AlgorithmPS256,
		func(key crypto.PrivateKey, msg []byte) ([]byte, error) {
			k, ok := key.(*rsa.PSSPrivateKey)
			if !ok {
				return nil, &ErrAlgMismatch{Expected: AlgorithmPS256, Got: algForPrivateKey(key)}
			}
			alg, err := rsaPSSAlgForHash(k.Public().Hash())
			if err != nil || alg != AlgorithmPS256 {
				return nil, &ErrAlgMismatch{Expected: AlgorithmPS256, Got: alg}
			}
			return k.Sign(msg)
		},
		func(key crypto.PublicKey, sig, msg []byte) (bool, error) {
			k, ok := key.(*rsa.PSSPublicKey)
			if !ok {
				return false, &ErrAlgMismatch{Expected: AlgorithmPS256, Got: algForPublicKey(key)}
			}
			alg, err := rsaPSSAlgForHash(k.Hash())
			if err != nil || alg != AlgorithmPS256 {
				return false, &ErrAlgMismatch{Expected: AlgorithmPS256, Got: alg}
			}
			return k.Verify(sig, msg), nil
		},
	)

	register(AlgorithmPS384,
		func(key crypto.PrivateKey, msg []byte) ([]byte, error) {
			k, ok := key.(*rsa.PSSPrivateKey)
			if !ok {
				return nil, &ErrAlgMismatch{Expected: AlgorithmPS384, Got: algForPrivateKey(key)}
			}
			alg, err := rsaPSSAlgForHash(k.Public().Hash())
			if err != nil || alg != AlgorithmPS384 {
				return nil, &ErrAlgMismatch{Expected: AlgorithmPS384, Got: alg}
			}
			return k.Sign(msg)
		},
		func(key crypto.PublicKey, sig, msg []byte) (bool, error) {
			k, ok := key.(*rsa.PSSPublicKey)
			if !ok {
				return false, &ErrAlgMismatch{Expected: AlgorithmPS384, Got: algForPublicKey(key)}
			}
			alg, err := rsaPSSAlgForHash(k.Hash())
			if err != nil || alg != AlgorithmPS384 {
				return false, &ErrAlgMismatch{Expected: AlgorithmPS384, Got: alg}
			}
			return k.Verify(sig, msg), nil
		},
	)

	register(AlgorithmPS512,
		func(key crypto.PrivateKey, msg []byte) ([]byte, error) {
			k, ok := key.(*rsa.PSSPrivateKey)
			if !ok {
				return nil, &ErrAlgMismatch{Expected: AlgorithmPS512, Got: algForPrivateKey(key)}
			}
			alg, err := rsaPSSAlgForHash(k.Public().Hash())
			if err != nil || alg != AlgorithmPS512 {
				return nil, &ErrAlgMismatch{Expected: AlgorithmPS512, Got: alg}
			}
			return k.Sign(msg)
		},
		func(key crypto.PublicKey, sig, msg []byte) (bool, error) {
			k, ok := key.(*rsa.PSSPublicKey)
			if !ok {
				return false, &ErrAlgMismatch{Expected: AlgorithmPS512, Got: algForPublicKey(key)}
			}
			alg, err := rsaPSSAlgForHash(k.Hash())
			if err != nil || alg != AlgorithmPS512 {
				return false, &ErrAlgMismatch{Expected: AlgorithmPS512, Got: alg}
			}
			return k.Verify(sig, msg), nil
		},
	)
}
