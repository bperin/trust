package signature

import (
	"crypto"

	"github.com/bperin/trust/crypto/ecdsa"
)

// init registers the ES256 and ES384 algorithms ([FIPS 186-4]
// (P-256) and [FIPS 186-4] (P-384)) for ECDSA signing and
// verification. ECDSA hashes internally — the message is passed
// directly to the key's Sign/Verify methods. The bound hash
// determines the algorithm: SHA-256 for ES256, SHA-384 for ES384.
func init() {
	register(AlgorithmES256,
		func(key crypto.PrivateKey, msg []byte) ([]byte, error) {
			k, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, &ErrAlgMismatch{Expected: AlgorithmES256, Got: algForPrivateKey(key)}
			}
			alg, err := ecdsaAlgForCurve(k.Curve())
			if err != nil || alg != AlgorithmES256 {
				return nil, &ErrAlgMismatch{Expected: AlgorithmES256, Got: alg}
			}
			return k.Sign(msg)
		},
		func(key crypto.PublicKey, sig, msg []byte) (bool, error) {
			k, ok := key.(*ecdsa.PublicKey)
			if !ok {
				return false, &ErrAlgMismatch{Expected: AlgorithmES256, Got: algForPublicKey(key)}
			}
			alg, err := ecdsaAlgForCurve(k.Curve())
			if err != nil || alg != AlgorithmES256 {
				return false, &ErrAlgMismatch{Expected: AlgorithmES256, Got: alg}
			}
			return k.Verify(sig, msg), nil
		},
	)

	register(AlgorithmES384,
		func(key crypto.PrivateKey, msg []byte) ([]byte, error) {
			k, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, &ErrAlgMismatch{Expected: AlgorithmES384, Got: algForPrivateKey(key)}
			}
			alg, err := ecdsaAlgForCurve(k.Curve())
			if err != nil || alg != AlgorithmES384 {
				return nil, &ErrAlgMismatch{Expected: AlgorithmES384, Got: alg}
			}
			return k.Sign(msg)
		},
		func(key crypto.PublicKey, sig, msg []byte) (bool, error) {
			k, ok := key.(*ecdsa.PublicKey)
			if !ok {
				return false, &ErrAlgMismatch{Expected: AlgorithmES384, Got: algForPublicKey(key)}
			}
			alg, err := ecdsaAlgForCurve(k.Curve())
			if err != nil || alg != AlgorithmES384 {
				return false, &ErrAlgMismatch{Expected: AlgorithmES384, Got: alg}
			}
			return k.Verify(sig, msg), nil
		},
	)
}
