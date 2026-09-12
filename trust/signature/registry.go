package signature

import (
	"crypto"
	"crypto/elliptic"
	"fmt"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/crypto/x25519"
)

// signFunc is a signing closure registered for an algorithm. It
// receives the private key and message, returns the signature or an
// error. The closure is responsible for type-asserting the key and
// performing any pre-hashing required by the algorithm.
type signFunc func(key crypto.PrivateKey, msg []byte) ([]byte, error)

// verifyFunc is a verification closure registered for an algorithm.
// It receives the public key, signature, and message, returns
// (true, nil) for a valid signature, (false, nil) for an invalid
// signature, and (false, error) for a structural failure (wrong key
// type, malformed signature). The closure is responsible for
// type-asserting the key and performing any pre-hashing required.
type verifyFunc func(key crypto.PublicKey, sig, msg []byte) (bool, error)

// registryEntry holds the sign and verify closures for one algorithm.
type registryEntry struct {
	sign   signFunc
	verify verifyFunc
}

// registry is the package-private algorithm registry. It is
// populated by init() in each per-algorithm file and is immutable
// after init. No consumer-facing registration API exists.
var registry = make(map[Algorithm]registryEntry)

// register adds a sign/verify entry for an algorithm. Called from
// init() in each per-algorithm file. Package-private — not exported
// to consumers. Must only be called from init(); the registry is
// read-only after package initialization.
func register(alg Algorithm, s signFunc, v verifyFunc) {
	registry[alg] = registryEntry{sign: s, verify: v}
}

// algForPrivateKey resolves the Algorithm for a private key,
// returning a zero Algorithm on failure. Used for ErrAlgMismatch.Got
// in sign closures where the key type does not match the algorithm.
func algForPrivateKey(key crypto.PrivateKey) Algorithm {
	alg, err := AlgorithmForPrivateKey(key)
	if err != nil {
		return 0
	}
	return alg
}

// algForPublicKey resolves the Algorithm for a public key,
// returning a zero Algorithm on failure. Used for ErrAlgMismatch.Got
// in verify closures where the key type does not match the algorithm.
func algForPublicKey(key crypto.PublicKey) Algorithm {
	alg, err := AlgorithmForPublicKey(key)
	if err != nil {
		return 0
	}
	return alg
}

// Sign produces a signature over msg using the given algorithm and
// private key. The algorithm must be registered and the key type
// must match the algorithm. Returns ErrAlgorithmNotRegistered if
// the algorithm has no registration, or ErrAlgMismatch if the key
// type does not match the algorithm.
func Sign(alg Algorithm, key crypto.PrivateKey, msg []byte) ([]byte, error) {
	entry, ok := registry[alg]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAlgorithmNotRegistered, algName(alg))
	}
	return entry.sign(key, msg)
}

// Verify checks a signature against msg using the given algorithm
// and public key. Returns (true, nil) for a valid signature,
// (false, nil) for an invalid signature, and (false, error) for a
// structural failure (unregistered algorithm, key/algorithm
// mismatch, malformed signature).
func Verify(alg Algorithm, key crypto.PublicKey, sig, msg []byte) (bool, error) {
	entry, ok := registry[alg]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrAlgorithmNotRegistered, algName(alg))
	}
	return entry.verify(key, sig, msg)
}

// AlgorithmForPrivateKey resolves the canonical Algorithm for a
// private key. The key's algorithm is fixed at construction and
// resolved through this function — the key type itself is not
// modified (avoids a circular import). Returns
// ErrUnsupportedAlgorithm for unrecognized key types or non-signing
// keys (e.g., x25519).
func AlgorithmForPrivateKey(key crypto.PrivateKey) (Algorithm, error) {
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		return AlgorithmEdDSA, nil
	case *secp256k1.PrivateKey:
		return AlgorithmES256K, nil
	case *ecdsa.PrivateKey:
		return ecdsaAlgForCurve(k.Curve())
	case *rsa.PSSPrivateKey:
		return rsaPSSAlgForHash(k.Public().Hash())
	case *rsa.PKCS1PrivateKey:
		return rsaPKCS1AlgForHash(k.Public().Hash())
	case *x25519.PrivateKey:
		return 0, fmt.Errorf("%w: x25519 is not a signing key", ErrUnsupportedAlgorithm)
	default:
		return 0, fmt.Errorf("%w: key type %T", ErrUnsupportedAlgorithm, key)
	}
}

// AlgorithmForPublicKey resolves the canonical Algorithm for a public
// key. The key's algorithm is fixed at construction and resolved
// through this function. Returns ErrUnsupportedAlgorithm for
// unrecognized key types or non-signing keys (e.g., x25519).
func AlgorithmForPublicKey(key crypto.PublicKey) (Algorithm, error) {
	switch k := key.(type) {
	case *ed25519.PublicKey:
		return AlgorithmEdDSA, nil
	case *secp256k1.PublicKey:
		return AlgorithmES256K, nil
	case *ecdsa.PublicKey:
		return ecdsaAlgForCurve(k.Curve())
	case *rsa.PSSPublicKey:
		return rsaPSSAlgForHash(k.Hash())
	case *rsa.PKCS1PublicKey:
		return rsaPKCS1AlgForHash(k.Hash())
	case *x25519.PublicKey:
		return 0, fmt.Errorf("%w: x25519 is not a signing key", ErrUnsupportedAlgorithm)
	default:
		return 0, fmt.Errorf("%w: key type %T", ErrUnsupportedAlgorithm, key)
	}
}

// ecdsaAlgForCurve maps an ECDSA bound curve to the canonical Algorithm.
func ecdsaAlgForCurve(curve elliptic.Curve) (Algorithm, error) {
	switch curve {
	case elliptic.P256():
		return AlgorithmES256, nil
	case elliptic.P384():
		return AlgorithmES384, nil
	default:
		return 0, fmt.Errorf("%w: unsupported ECDSA curve", ErrUnsupportedAlgorithm)
	}
}

// rsaPSSAlgForHash maps an RSA-PSS bound hash to the canonical Algorithm.
func rsaPSSAlgForHash(hash crypto.Hash) (Algorithm, error) {
	switch hash {
	case crypto.SHA256:
		return AlgorithmPS256, nil
	case crypto.SHA384:
		return AlgorithmPS384, nil
	case crypto.SHA512:
		return AlgorithmPS512, nil
	default:
		return 0, fmt.Errorf("%w: unsupported RSA-PSS hash %s", ErrUnsupportedAlgorithm, hash)
	}
}

// rsaPKCS1AlgForHash maps an RSA-PKCS1v1.5 bound hash to the canonical
// Algorithm.
func rsaPKCS1AlgForHash(hash crypto.Hash) (Algorithm, error) {
	switch hash {
	case crypto.SHA256:
		return AlgorithmRS256, nil
	case crypto.SHA384:
		return AlgorithmRS384, nil
	case crypto.SHA512:
		return AlgorithmRS512, nil
	default:
		return 0, fmt.Errorf("%w: unsupported RSA-PKCS1 hash %s", ErrUnsupportedAlgorithm, hash)
	}
}
