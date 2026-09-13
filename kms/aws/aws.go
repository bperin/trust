//go:build aws_kms

// Package aws implements a [RemoteSigner] backed by AWS KMS for a
// secp256k1 asymmetric signing key. AWS KMS returns DER-encoded
// ECDSA-Sig-Value per [SEC 1 v2] §2.3.3; this adapter parses the DER
// to raw r||s, normalizes low-s per [EIP-2], and — for the EVM path —
// computes the recovery id by trying recID 0–3 per [SEC 1 v2] §4.3.3.
//
// The signer holds only a key ID string and an AWS KMS client — no
// private key material is present in the process. The public key is
// fetched and cached on first use so the recovery id can be computed.
//
// Build tag: aws_kms. This file is excluded from the default build so
// the kms module compiles with no cloud SDK dependency.
package aws

import (
	"context"
	"fmt"
	"sync"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/bperin/kms"
	"github.com/bperin/kms/der"

	"github.com/bperin/trust/crypto/secp256k1"
)

// AWSSigner signs digests with a secp256k1 key held in AWS KMS. It
// implements [kms.RemoteSigner]. The struct holds only a key ID and
// an AWS KMS client — no private key material.
type AWSSigner struct {
	// keyID is the AWS KMS key identifier or key ARN. It is a
	// reference, never key material.
	keyID string

	// client is the AWS KMS client used for Sign and GetPublicKey
	// calls. The caller constructs and configures it (region,
	// credentials).
	client *awskms.Client

	// pub caches the secp256k1 public key fetched from AWS KMS. It is
	// populated lazily on first PublicKey or EVM-path Sign call.
	pubOnce sync.Once
	pub     *secp256k1.PublicKey
	pubErr  error
}

// NewAWSSigner returns an AWSSigner for the given AWS KMS key ID and
// client. The client must be configured with credentials and region
// sufficient to call Sign and GetPublicKey on the key. No key
// material is stored — only the key ID reference.
func NewAWSSigner(keyID string, client *awskms.Client) *AWSSigner {
	return &AWSSigner{keyID: keyID, client: client}
}

// Sign signs a 32-byte pre-computed digest with the AWS KMS key. The
// SignOptions.Path field selects the output wire format:
//
//   - kms.SignPathJOSE: returns 64-byte r||s.
//   - kms.SignPathEVM:  returns 65-byte r||s||v, where v is the
//     [SEC 1 v2] §4.3.3 recovery id.
//
// AWS KMS is called with MessageType DIGEST and SigningAlgorithm
// ECDSA_SHA_256. The DER response is parsed via der.ParseECDSASignature
// and normalized to low-s via der.NormalizeLowS. For the EVM path the
// recovery id is computed via kms.ComputeRecoveryID on the normalized
// signature.
func (s *AWSSigner) Sign(ctx context.Context, digest []byte, opts kms.SignOptions) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("aws: digest must be 32 bytes, got %d", len(digest))
	}

	out, err := s.client.Sign(ctx, &awskms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("aws: KMS Sign failed: %w", err)
	}

	r, sBytes, err := der.ParseECDSASignature(out.Signature)
	if err != nil {
		return nil, fmt.Errorf("aws: parse DER signature: %w", err)
	}

	sNorm, flipped := der.NormalizeLowS(sBytes)

	// Build the 64-byte r||s. Left-pad r and s to 32 bytes each —
	// DER integers may be shorter than 32 bytes when leading bytes are
	// zero (e.g. a small r).
	sig := make([]byte, 64)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(sNorm):64], sNorm)

	switch opts.Path {
	case kms.SignPathJOSE:
		return sig, nil
	case kms.SignPathEVM:
		pub, err := s.PublicKey(ctx)
		if err != nil {
			return nil, err
		}
		recID, err := kms.ComputeRecoveryID(sig, digest, pub)
		if err != nil {
			return nil, fmt.Errorf("aws: %w", err)
		}
		// ComputeRecoveryID operates on the normalized r||sNorm
		// signature, so the returned recID is already correct for
		// the low-s form. Do NOT XOR by flipped — that double-corrects.
		_ = flipped
		out := make([]byte, 65)
		copy(out[:64], sig)
		out[64] = recID
		return out, nil
	default:
		return nil, fmt.Errorf("aws: unknown sign path %d", opts.Path)
	}
}

// PublicKey returns the secp256k1 public key for the AWS KMS key,
// fetched via GetPublicKey and cached. The public key is required to
// compute the recovery id for the EVM path.
func (s *AWSSigner) PublicKey(ctx context.Context) (*secp256k1.PublicKey, error) {
	s.pubOnce.Do(func() {
		s.pubErr = s.loadPublicKey(ctx)
	})
	if s.pubErr != nil {
		return nil, s.pubErr
	}
	return s.pub, nil
}

// loadPublicKey fetches the public key DER from AWS KMS and parses it.
// It is called once under pubOnce.
func (s *AWSSigner) loadPublicKey(ctx context.Context) error {
	out, err := s.client.GetPublicKey(ctx, &awskms.GetPublicKeyInput{
		KeyId: &s.keyID,
	})
	if err != nil {
		return fmt.Errorf("aws: KMS GetPublicKey failed: %w", err)
	}
	pub, err := kms.ParsePublicKeyDER(out.PublicKey)
	if err != nil {
		return fmt.Errorf("aws: parse public key DER: %w", err)
	}
	s.pub = pub
	return nil
}

// Compile-time interface conformance.
var _ kms.RemoteSigner = (*AWSSigner)(nil)
