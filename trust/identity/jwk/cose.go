package jwkutil

import (
	"crypto"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/signature"
	"github.com/fxamacker/cbor/v2"
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

type CoseSignOptions struct {
	Algorithm int64
	Protected map[int64]any
}

type CoseVerifyOptions struct {
	Algorithm int64
}

// CoseSign implements RFC 9052 COSE_Sign1 signing.
func CoseSign(payload []byte, key crypto.PrivateKey, opts CoseSignOptions) ([]byte, error) {
	if opts.Algorithm == 0 {
		return nil, fmt.Errorf("cose sign: %w", ErrAlgRequired)
	}

	prot := make(map[int64]any)
	for k, v := range opts.Protected {
		if k == 1 {
			return nil, fmt.Errorf("cose sign: alg (label 1) cannot be set in protected options directly")
		}
		prot[k] = v
	}
	prot[1] = opts.Algorithm

	canonicalOpts := cbor.CanonicalEncOptions()
	enc, err := canonicalOpts.EncMode()
	if err != nil {
		return nil, fmt.Errorf("cose sign: enc mode: %w", err)
	}

	protBytes, err := enc.Marshal(prot)
	if err != nil {
		return nil, fmt.Errorf("cose sign: marshal protected header: %w", err)
	}

	// Sig_structure = ["Signature1", protected, external_aad, payload]
	sigStruct := []any{
		"Signature1",
		protBytes,
		[]byte{},
		payload,
	}

	sigStructBytes, err := enc.Marshal(sigStruct)
	if err != nil {
		return nil, fmt.Errorf("cose sign: marshal sig_structure: %w", err)
	}

	signature, err := signCosePayload(opts.Algorithm, key, sigStructBytes)
	if err != nil {
		return nil, fmt.Errorf("cose sign: %w", err)
	}

	// COSE_Sign1 = [ protected, unprotected, payload, signature ]
	coseObj := []any{
		protBytes,
		map[int64]any{},
		payload,
		signature,
	}

	return enc.Marshal(coseObj)
}

// CoseVerify implements RFC 9052 COSE_Sign1 verification.
func CoseVerify(cose []byte, key crypto.PublicKey, opts CoseVerifyOptions) ([]byte, error) {
	var coseObj []any
	if err := cbor.Unmarshal(cose, &coseObj); err != nil {
		return nil, fmt.Errorf("%w: unmarshal COSE_Sign1: %v", ErrCoseMalformed, err)
	}
	if len(coseObj) != 4 {
		return nil, fmt.Errorf("%w: expected 4 elements, got %d", ErrCoseMalformed, len(coseObj))
	}

	protBytes, ok := coseObj[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: protected header is not bstr", ErrCoseMalformed)
	}

	payload, ok := coseObj[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: payload is not bstr", ErrCoseMalformed)
	}

	signature, ok := coseObj[3].([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: signature is not bstr", ErrCoseMalformed)
	}

	var prot map[int64]any
	if err := cbor.Unmarshal(protBytes, &prot); err != nil {
		return nil, fmt.Errorf("%w: unmarshal protected header: %v", ErrCoseMalformed, err)
	}

	algVal, ok := prot[1]
	if !ok {
		return nil, ErrCoseAlgMissing
	}

	var alg int64
	switch v := algVal.(type) {
	case int:
		alg = int64(v)
	case int64:
		alg = v
	case uint64:
		alg = int64(v)
	default:
		return nil, fmt.Errorf("%w: alg header has invalid type %T", ErrCoseMalformed, algVal)
	}

	if opts.Algorithm != 0 && opts.Algorithm != alg {
		return nil, fmt.Errorf("%w: expected alg %d, got %d", ErrAlgMismatch, opts.Algorithm, alg)
	}

	canonicalOpts := cbor.CanonicalEncOptions()
	enc, err := canonicalOpts.EncMode()
	if err != nil {
		return nil, fmt.Errorf("cose verify: enc mode: %w", err)
	}

	sigStruct := []any{
		"Signature1",
		protBytes,
		[]byte{},
		payload,
	}

	sigStructBytes, err := enc.Marshal(sigStruct)
	if err != nil {
		return nil, fmt.Errorf("cose verify: marshal sig_structure: %w", err)
	}

	if err := verifyCoseSignature(alg, key, sigStructBytes, signature); err != nil {
		return nil, err
	}

	return payload, nil
}

func signCosePayload(alg int64, key crypto.PrivateKey, sigStructBytes []byte) ([]byte, error) {
	// Derive the expected algorithm from the key and validate against alg.
	derived, err := signature.AlgorithmForPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAlg, err)
	}
	if derived.COSE() != alg {
		return nil, fmt.Errorf("%w: key signs %d, got %d", ErrAlgMismatch, derived.COSE(), alg)
	}

	// Sign with the key. ECDSA produces DER; COSE uses fixed-width R||S.
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		return k.Sign(sigStructBytes), nil
	case *secp256k1.PrivateKey:
		digest := crypto.SHA256.New()
		digest.Write(sigStructBytes)
		return k.Sign(digest.Sum(nil))
	case *ecdsa.PrivateKey:
		der, err := k.Sign(sigStructBytes)
		if err != nil {
			return nil, err
		}
		size := ecdsaSigSize(k.Public().Curve())
		return derToFixed(der, size)
	case *rsa.PSSPrivateKey:
		return k.Sign(sigStructBytes)
	case *rsa.PKCS1PrivateKey:
		return k.Sign(sigStructBytes)
	default:
		return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlg, key)
	}
}

func verifyCoseSignature(alg int64, key crypto.PublicKey, sigStructBytes, sig []byte) error {
	// Derive the expected algorithm from the key and validate against alg.
	derived, err := signature.AlgorithmForPublicKey(key)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupportedAlg, err)
	}
	if derived.COSE() != alg {
		return fmt.Errorf("%w: key expects %d, got %d", ErrAlgMismatch, derived.COSE(), alg)
	}

	// Verify with the key. COSE ECDSA signatures are fixed-width R||S;
	// convert to DER for the key's Verify method.
	switch pub := key.(type) {
	case ed25519.PublicKey:
		if !pub.Verify(sig, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case *ed25519.PublicKey:
		if pub == nil {
			return ErrCoseInvalidSig
		}
		if !pub.Verify(sig, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case secp256k1.PublicKey:
		digest := crypto.SHA256.New()
		digest.Write(sigStructBytes)
		if !pub.Verify(sig, digest.Sum(nil)) {
			return ErrCoseInvalidSig
		}
		return nil
	case *secp256k1.PublicKey:
		if pub == nil {
			return ErrCoseInvalidSig
		}
		digest := crypto.SHA256.New()
		digest.Write(sigStructBytes)
		if !pub.Verify(sig, digest.Sum(nil)) {
			return ErrCoseInvalidSig
		}
		return nil
	case ecdsa.PublicKey:
		size := ecdsaSigSize(pub.Curve())
		der, err := fixedToDer(sig, size)
		if err != nil {
			return err
		}
		if !pub.Verify(der, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case *ecdsa.PublicKey:
		if pub == nil {
			return ErrCoseInvalidSig
		}
		size := ecdsaSigSize(pub.Curve())
		der, err := fixedToDer(sig, size)
		if err != nil {
			return err
		}
		if !pub.Verify(der, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case rsa.PSSPublicKey:
		if !pub.Verify(sig, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case *rsa.PSSPublicKey:
		if pub == nil {
			return ErrCoseInvalidSig
		}
		if !pub.Verify(sig, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case rsa.PKCS1PublicKey:
		if !pub.Verify(sig, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case *rsa.PKCS1PublicKey:
		if pub == nil {
			return ErrCoseInvalidSig
		}
		if !pub.Verify(sig, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported public key type %T", ErrUnsupportedAlg, key)
	}
}

// ecdsaSigSize returns the fixed-width byte size for ECDSA signatures
// (R || S) based on the curve's byte order size.
func ecdsaSigSize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}
