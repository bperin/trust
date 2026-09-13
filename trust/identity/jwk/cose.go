// Package jwkutil COSE_Sign1 adapter. This file implements COSE_Sign1
// (RFC 9052) signing and verification as a thin adapter over
// github.com/veraison/go-cose v1.3.0.
//
// Spike decision (PLAN-004-spike-ws2): ISOLATE. go-cose is vetted,
// maintained, and adds zero new transitive deps (depends only on
// fxamacker/cbor and x448/float16, both already present). It covers
// the standard algorithm set (EdDSA, ES256, ES384, PS256, PS384,
// PS512) with built-in Signer/Verifier implementations. Two gaps
// require custom adapters that implement go-cose's Signer/Verifier
// interfaces:
//
//   - ES256K (secp256k1, alg -47): go-cose does not recognize this
//     algorithm. The adapter delegates to trust's existing
//     secp256k1 package (SHA-256 pre-hash, low-s canonicalization per
//     EIP-2).
//   - RS256/RS384/RS512 (RSA PKCS#1 v1.5, algs -257/-258/-259):
//     go-cose defines these constants but ships no built-in
//     signer/verifier. The adapter delegates to trust's existing
//     rsa.PKCS1PrivateKey / rsa.PKCS1PublicKey.
//
// COSE_Sign1 construction and serialization (wire-format munging)
// remain in this file, not in the signature package. No go-cose
// types leak through the public API.
package jwkutil

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	trustrsa "github.com/bperin/trust/trust/crypto/rsa"
	"github.com/bperin/trust/trust/crypto/secp256k1"
	"github.com/bperin/trust/trust/signature"
	"github.com/veraison/go-cose"
)

// COSE algorithm identifiers (RFC 9053)
const (
	AlgEdDSA  = -8
	AlgES256  = -7
	AlgES384  = -35
	AlgES256K = -47
	AlgPS256  = -37
	AlgPS384  = -38
	AlgPS512  = -39
	AlgRS256  = -257
	AlgRS384  = -258
	AlgRS512  = -259
)

var (
	ErrCoseMalformed  = errors.New("cose: malformed COSE_Sign1 structure")
	ErrCoseAlgMissing = errors.New("cose: missing alg in protected header")
	ErrCoseInvalidSig = errors.New("cose: invalid COSE signature")
)

// CoseSignOptions configures CoseSign.
type CoseSignOptions struct {
	Algorithm int64
	Protected map[int64]any
}

// CoseVerifyOptions configures CoseVerify.
type CoseVerifyOptions struct {
	Algorithm int64
}

// CoseSign implements RFC 9052 COSE_Sign1 signing. It delegates the
// Sig_structure construction, protected header marshaling, and
// COSE_Sign1 array serialization to github.com/veraison/go-cose.
// Standard algorithms (EdDSA, ES256, ES384, PS256, PS384, PS512) use
// go-cose's built-in signers. ES256K and RS256/384/512 use custom
// Signer adapters that delegate to trust's existing crypto packages.
//
// The output is an untagged COSE_Sign1 CBOR array (no CBOR tag 18
// prefix), matching the prior wire format.
func CoseSign(payload []byte, key crypto.PrivateKey, opts CoseSignOptions) ([]byte, error) {
	if opts.Algorithm == 0 {
		return nil, fmt.Errorf("cose sign: %w", ErrAlgRequired)
	}

	// Validate the algorithm against the key type before any crypto
	// work. The algorithm is never taken from the payload or headers.
	keyAlg, err := signature.AlgorithmForPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("cose sign: %w", err)
	}
	if keyAlg.COSE() != opts.Algorithm {
		return nil, fmt.Errorf("cose sign: %w: key signs %d, got %d",
			ErrAlgMismatch, keyAlg.COSE(), opts.Algorithm)
	}

	signer, err := newCoseSigner(opts.Algorithm, key)
	if err != nil {
		return nil, fmt.Errorf("cose sign: %w", err)
	}

	// Build the protected header. The alg label (1) is controlled by
	// the signer; the caller may not set it directly.
	protected := cose.ProtectedHeader{}
	for k, v := range opts.Protected {
		if k == 1 {
			return nil, fmt.Errorf("cose sign: alg (label 1) cannot be set in protected options directly")
		}
		protected[k] = v
	}
	protected.SetAlgorithm(cose.Algorithm(opts.Algorithm))

	msg := cose.UntaggedSign1Message{
		Headers: cose.Headers{
			Protected:   protected,
			Unprotected: cose.UnprotectedHeader{},
		},
		Payload: payload,
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("cose sign: %w", err)
	}

	return msg.MarshalCBOR()
}

// CoseVerify implements RFC 9052 COSE_Sign1 verification. It accepts
// both tagged (CBOR tag 18) and untagged COSE_Sign1 messages. The
// protected header's alg must match the key type; an optional
// opts.Algorithm pins it a second time. Standard algorithms delegate
// to go-cose's built-in verifiers; ES256K and RS256/384/512 use
// custom Verifier adapters.
func CoseVerify(coseBytes []byte, key crypto.PublicKey, opts CoseVerifyOptions) ([]byte, error) {
	if len(coseBytes) == 0 {
		return nil, fmt.Errorf("%w: empty input", ErrCoseMalformed)
	}

	var msg cose.Sign1Message
	if coseBytes[0] == 0xd2 {
		// Tagged COSE_Sign1 (tag 18).
		if err := msg.UnmarshalCBOR(coseBytes); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCoseMalformed, err)
		}
	} else {
		// Untagged COSE_Sign1.
		var untagged cose.UntaggedSign1Message
		if err := untagged.UnmarshalCBOR(coseBytes); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCoseMalformed, err)
		}
		msg = cose.Sign1Message(untagged)
	}

	// Extract alg from the protected header.
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		if errors.Is(err, cose.ErrAlgorithmNotFound) {
			return nil, ErrCoseAlgMissing
		}
		return nil, fmt.Errorf("%w: %v", ErrCoseMalformed, err)
	}
	algInt := int64(alg)

	// Caller-pinned algorithm check.
	if opts.Algorithm != 0 && opts.Algorithm != algInt {
		return nil, fmt.Errorf("%w: expected alg %d, got %d",
			ErrAlgMismatch, opts.Algorithm, algInt)
	}

	// Key-type algorithm check. The key's bound algorithm must match
	// the protected header's alg — the alg header is never trusted
	// blindly.
	keyAlg, err := signature.AlgorithmForPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("cose verify: %w: key type %T", ErrUnsupportedAlg, key)
	}
	if keyAlg.COSE() != algInt {
		return nil, fmt.Errorf("cose verify: %w: key expects %d, got %d",
			ErrAlgMismatch, keyAlg.COSE(), algInt)
	}

	verifier, err := newCoseVerifier(algInt, key)
	if err != nil {
		return nil, fmt.Errorf("cose verify: %w", err)
	}

	if err := msg.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("cose verify: %w", ErrCoseInvalidSig)
	}

	return msg.Payload, nil
}

// newCoseSigner builds a go-cose Signer for the given algorithm and
// trust private key. Standard algorithms convert the trust key to a
// stdlib crypto.Signer and delegate to cose.NewSigner. ES256K and
// RS256/384/512 use custom adapters.
func newCoseSigner(alg int64, key crypto.PrivateKey) (cose.Signer, error) {
	switch alg {
	case AlgEdDSA, AlgES256, AlgES384, AlgPS256, AlgPS384, AlgPS512:
		rawKey, err := toStdlibPrivateKey(key, "")
		if err != nil {
			return nil, err
		}
		signer, ok := rawKey.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlg, key)
		}
		return cose.NewSigner(cose.Algorithm(alg), signer)

	case AlgES256K:
		k, ok := key.(*secp256k1.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlg, key)
		}
		return &es256kSigner{key: k}, nil

	case AlgRS256, AlgRS384, AlgRS512:
		k, ok := key.(*trustrsa.PKCS1PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlg, key)
		}
		return &rsPKCS1Signer{alg: cose.Algorithm(alg), key: k}, nil

	default:
		return nil, fmt.Errorf("%w: alg %d", ErrUnsupportedAlg, alg)
	}
}

// newCoseVerifier builds a go-cose Verifier for the given algorithm
// and trust public key. Standard algorithms convert the trust key to
// a stdlib crypto.PublicKey and delegate to cose.NewVerifier. ES256K
// and RS256/384/512 use custom adapters.
func newCoseVerifier(alg int64, key crypto.PublicKey) (cose.Verifier, error) {
	switch alg {
	case AlgEdDSA, AlgES256, AlgES384, AlgPS256, AlgPS384, AlgPS512:
		rawKey, err := toStdlibPublicKey(key)
		if err != nil {
			return nil, err
		}
		return cose.NewVerifier(cose.Algorithm(alg), rawKey)

	case AlgES256K:
		k, ok := key.(*secp256k1.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlg, key)
		}
		return &es256kVerifier{key: k}, nil

	case AlgRS256, AlgRS384, AlgRS512:
		k, ok := key.(*trustrsa.PKCS1PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlg, key)
		}
		return &rsPKCS1Verifier{alg: cose.Algorithm(alg), key: k}, nil

	default:
		return nil, fmt.Errorf("%w: alg %d", ErrUnsupportedAlg, alg)
	}
}

// --- ES256K (secp256k1) custom Signer/Verifier ---

// es256kSigner implements cose.Signer for ES256K (secp256k1 ECDSA
// w/ SHA-256). go-cose has no built-in support for this algorithm.
// The adapter delegates to trust's secp256k1.PrivateKey.Sign, which
// uses RFC 6979 deterministic nonces and EIP-2 low-s canonicalization.
type es256kSigner struct {
	key *secp256k1.PrivateKey
}

// Algorithm returns the COSE algorithm identifier for ES256K.
func (s *es256kSigner) Algorithm() cose.Algorithm {
	return cose.Algorithm(AlgES256K)
}

// Sign signs content with SHA-256 pre-hashing, then delegates to the
// trust secp256k1 private key. The signature is 64 bytes: r (32) ||
// s (32), the COSE ECDSA signature format.
func (s *es256kSigner) Sign(_ io.Reader, content []byte) ([]byte, error) {
	digest := crypto.SHA256.New()
	digest.Write(content)
	return s.key.Sign(digest.Sum(nil))
}

// es256kVerifier implements cose.Verifier for ES256K.
type es256kVerifier struct {
	key *secp256k1.PublicKey
}

// Algorithm returns the COSE algorithm identifier for ES256K.
func (v *es256kVerifier) Algorithm() cose.Algorithm {
	return cose.Algorithm(AlgES256K)
}

// Verify SHA-256 pre-hashes content, then delegates to the trust
// secp256k1 public key. Returns cose.ErrVerification on failure.
func (v *es256kVerifier) Verify(content, sig []byte) error {
	digest := crypto.SHA256.New()
	digest.Write(content)
	if !v.key.Verify(sig, digest.Sum(nil)) {
		return cose.ErrVerification
	}
	return nil
}

// --- RS256/384/512 (RSA PKCS#1 v1.5) custom Signer/Verifier ---

// rsPKCS1Signer implements cose.Signer for RS256/RS384/RS512 (RSA
// PKCS#1 v1.5). go-cose defines these algorithm constants but ships
// no built-in signer. The adapter delegates to trust's
// rsa.PKCS1PrivateKey.Sign, which hashes with the bound hash and
// signs with PKCS#1 v1.5.
type rsPKCS1Signer struct {
	alg cose.Algorithm
	key *trustrsa.PKCS1PrivateKey
}

// Algorithm returns the COSE algorithm identifier.
func (s *rsPKCS1Signer) Algorithm() cose.Algorithm {
	return s.alg
}

// Sign delegates to the trust PKCS#1 private key, which pre-hashes
// with the bound hash and signs with PKCS#1 v1.5. PKCS#1 v1.5 is
// deterministic: the rand parameter is unused.
func (s *rsPKCS1Signer) Sign(_ io.Reader, content []byte) ([]byte, error) {
	return s.key.Sign(content)
}

// rsPKCS1Verifier implements cose.Verifier for RS256/RS384/RS512.
type rsPKCS1Verifier struct {
	alg cose.Algorithm
	key *trustrsa.PKCS1PublicKey
}

// Algorithm returns the COSE algorithm identifier.
func (v *rsPKCS1Verifier) Algorithm() cose.Algorithm {
	return v.alg
}

// Verify delegates to the trust PKCS#1 public key, which pre-hashes
// with the bound hash and verifies with PKCS#1 v1.5. Returns
// cose.ErrVerification on failure.
func (v *rsPKCS1Verifier) Verify(content, sig []byte) error {
	if !v.key.Verify(sig, content) {
		return cose.ErrVerification
	}
	return nil
}
