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

// signFunc is a signing closure registered for an algorithm. The
// closure type-asserts the key and performs any pre-hashing the
// algorithm requires.
type signFunc func(key crypto.PrivateKey, msg []byte) ([]byte, error)

// verifyFunc is a verification closure registered for an algorithm.
// It returns (true, nil) for a valid signature, (false, nil) for an
// invalid signature, and (false, error) for a structural failure
// such as a wrong key type or malformed signature.
type verifyFunc func(key crypto.PublicKey, sig, msg []byte) (bool, error)

// registryEntry holds the sign and verify closures for one algorithm.
type registryEntry struct {
	sign   signFunc
	verify verifyFunc
}

// registry maps each Algorithm to its sign/verify closures. It is
// populated by init() and is read-only after package
// initialization.
var registry = make(map[Algorithm]registryEntry)

// register adds a sign/verify entry for an algorithm. It must only
// be called from init().
func register(alg Algorithm, s signFunc, v verifyFunc) {
	registry[alg] = registryEntry{sign: s, verify: v}
}

// algForPrivateKey resolves the Algorithm for a private key,
// returning the zero Algorithm on failure.
func algForPrivateKey(key crypto.PrivateKey) Algorithm {
	alg, err := AlgorithmForPrivateKey(key)
	if err != nil {
		return 0
	}
	return alg
}

// algForPublicKey resolves the Algorithm for a public key,
// returning the zero Algorithm on failure.
func algForPublicKey(key crypto.PublicKey) Algorithm {
	alg, err := AlgorithmForPublicKey(key)
	if err != nil {
		return 0
	}
	return alg
}

// Sign produces a signature over msg using the given algorithm and
// private key. It returns ErrAlgorithmNotRegistered if the algorithm
// has no registration, or ErrAlgMismatch if the key type does not
// match the algorithm.
func Sign(alg Algorithm, key crypto.PrivateKey, msg []byte) ([]byte, error) {
	entry, ok := registry[alg]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAlgorithmNotRegistered, algName(alg))
	}
	return entry.sign(key, msg)
}

// Verify checks a signature against msg using the given algorithm
// and public key. It returns (true, nil) for a valid signature,
// (false, nil) for an invalid signature, and (false, error) for a
// structural failure.
func Verify(alg Algorithm, key crypto.PublicKey, sig, msg []byte) (bool, error) {
	entry, ok := registry[alg]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrAlgorithmNotRegistered, algName(alg))
	}
	return entry.verify(key, sig, msg)
}

// AlgorithmForPrivateKey resolves the canonical Algorithm for a
// private key. It returns ErrUnsupportedAlgorithm for unrecognized
// key types or non-signing keys (e.g., x25519).
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

// AlgorithmForPublicKey resolves the canonical Algorithm for a
// public key. It returns ErrUnsupportedAlgorithm for unrecognized
// key types or non-signing keys (e.g., x25519).
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
