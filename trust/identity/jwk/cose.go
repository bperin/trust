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
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		if alg != AlgEdDSA {
			return nil, fmt.Errorf("%w: Ed25519 keys sign EdDSA (-8), got %d", ErrAlgMismatch, alg)
		}
		return k.Sign(sigStructBytes), nil
	case *secp256k1.PrivateKey:
		if alg != AlgES256K && alg != -46 {
			return nil, fmt.Errorf("%w: secp256k1 keys sign ES256K (-47), got %d", ErrAlgMismatch, alg)
		}
		digest := crypto.SHA256.New()
		digest.Write(sigStructBytes)
		return k.Sign(digest.Sum(nil))
	case *ecdsa.PrivateKey:
		size, curve, err := ecdsaCoseParamsForAlg(alg)
		if err != nil {
			return nil, err
		}
		if k.Public().Curve() != curve {
			return nil, fmt.Errorf("%w: curve %v does not sign alg %d", ErrAlgMismatch, k.Public().Curve(), alg)
		}
		der, err := k.Sign(sigStructBytes)
		if err != nil {
			return nil, err
		}
		return derToFixed(der, size)
	case *rsa.PSSPrivateKey:
		wantAlg, err := rsaCoseAlgForHash(k.Public().Hash())
		if err != nil || alg != wantAlg {
			return nil, fmt.Errorf("%w: PSS key with %v signs %d, got %d", ErrAlgMismatch, k.Public().Hash(), wantAlg, alg)
		}
		return k.Sign(sigStructBytes)
	case *rsa.PKCS1PrivateKey:
		wantAlg, err := rsaPKCS1CoseAlgForHash(k.Public().Hash())
		if err != nil || alg != wantAlg {
			return nil, fmt.Errorf("%w: PKCS1 key with %v signs %d, got %d", ErrAlgMismatch, k.Public().Hash(), wantAlg, alg)
		}
		return k.Sign(sigStructBytes)
	default:
		return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlg, key)
	}
}

func verifyCoseSignature(alg int64, key crypto.PublicKey, sigStructBytes, signature []byte) error {
	switch pub := key.(type) {
	case ed25519.PublicKey:
		if alg != AlgEdDSA {
			return fmt.Errorf("%w: Ed25519 expects alg -8", ErrAlgMismatch)
		}
		if !pub.Verify(signature, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case *ed25519.PublicKey:
		if pub == nil {
			return ErrCoseInvalidSig
		}
		if alg != AlgEdDSA {
			return fmt.Errorf("%w: Ed25519 expects alg -8", ErrAlgMismatch)
		}
		if !pub.Verify(signature, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case secp256k1.PublicKey:
		if alg != AlgES256K && alg != -46 {
			return fmt.Errorf("%w: secp256k1 expects alg -47", ErrAlgMismatch)
		}
		digest := crypto.SHA256.New()
		digest.Write(sigStructBytes)
		if !pub.Verify(signature, digest.Sum(nil)) {
			return ErrCoseInvalidSig
		}
		return nil
	case *secp256k1.PublicKey:
		if pub == nil {
			return ErrCoseInvalidSig
		}
		if alg != AlgES256K && alg != -46 {
			return fmt.Errorf("%w: secp256k1 expects alg -47", ErrAlgMismatch)
		}
		digest := crypto.SHA256.New()
		digest.Write(sigStructBytes)
		if !pub.Verify(signature, digest.Sum(nil)) {
			return ErrCoseInvalidSig
		}
		return nil
	case ecdsa.PublicKey:
		size, curve, err := ecdsaCoseParamsForAlg(alg)
		if err != nil {
			return err
		}
		if pub.Curve() != curve {
			return fmt.Errorf("%w: curve mismatch", ErrAlgMismatch)
		}
		der, err := fixedToDer(signature, size)
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
		size, curve, err := ecdsaCoseParamsForAlg(alg)
		if err != nil {
			return err
		}
		if pub.Curve() != curve {
			return fmt.Errorf("%w: curve mismatch", ErrAlgMismatch)
		}
		der, err := fixedToDer(signature, size)
		if err != nil {
			return err
		}
		if !pub.Verify(der, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case rsa.PSSPublicKey:
		wantAlg, err := rsaCoseAlgForHash(pub.Hash())
		if err != nil || alg != wantAlg {
			return fmt.Errorf("%w: RSA PSS alg mismatch", ErrAlgMismatch)
		}
		if !pub.Verify(signature, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case *rsa.PSSPublicKey:
		if pub == nil {
			return ErrCoseInvalidSig
		}
		wantAlg, err := rsaCoseAlgForHash(pub.Hash())
		if err != nil || alg != wantAlg {
			return fmt.Errorf("%w: RSA PSS alg mismatch", ErrAlgMismatch)
		}
		if !pub.Verify(signature, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case rsa.PKCS1PublicKey:
		wantAlg, err := rsaPKCS1CoseAlgForHash(pub.Hash())
		if err != nil || alg != wantAlg {
			return fmt.Errorf("%w: RSA PKCS1 alg mismatch", ErrAlgMismatch)
		}
		if !pub.Verify(signature, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	case *rsa.PKCS1PublicKey:
		if pub == nil {
			return ErrCoseInvalidSig
		}
		wantAlg, err := rsaPKCS1CoseAlgForHash(pub.Hash())
		if err != nil || alg != wantAlg {
			return fmt.Errorf("%w: RSA PKCS1 alg mismatch", ErrAlgMismatch)
		}
		if !pub.Verify(signature, sigStructBytes) {
			return ErrCoseInvalidSig
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported public key type %T", ErrUnsupportedAlg, key)
	}
}

func ecdsaCoseParamsForAlg(alg int64) (int, elliptic.Curve, error) {
	switch alg {
	case AlgES256:
		return 32, elliptic.P256(), nil
	case AlgES384:
		return 48, elliptic.P384(), nil
	default:
		return 0, nil, fmt.Errorf("%w: unsupported ECDSA alg %d", ErrAlgMismatch, alg)
	}
}

func rsaCoseAlgForHash(h crypto.Hash) (int64, error) {
	switch h {
	case crypto.SHA256:
		return AlgPS256, nil
	case crypto.SHA384:
		return AlgPS384, nil
	case crypto.SHA512:
		return AlgPS512, nil
	default:
		return 0, fmt.Errorf("%w: unsupported RSA hash %v", ErrUnsupportedAlg, h)
	}
}

func rsaPKCS1CoseAlgForHash(h crypto.Hash) (int64, error) {
	switch h {
	case crypto.SHA256:
		return AlgRS256, nil
	case crypto.SHA384:
		return AlgRS384, nil
	case crypto.SHA512:
		return AlgRS512, nil
	default:
		return 0, fmt.Errorf("%w: unsupported RSA PKCS1 hash %v", ErrUnsupportedAlg, h)
	}
}
