//go:build gcp_kms

// Package gcp implements a [RemoteSigner] backed by GCP KMS for a
// secp256k1 asymmetric signing key. GCP KMS returns DER-encoded
// ECDSA-Sig-Value per [SEC 1 v2] §2.3.3; this adapter parses the DER
// to raw r||s, normalizes low-s per [EIP-2], and — for the EVM path —
// computes the recovery id by trying recID 0–3 per [SEC 1 v2] §4.3.3.
//
// The signer holds only a key name and a GCP KMS client — no private
// key material is present in the process. The public key is fetched
// and cached on first use so the recovery id can be computed.
//
// Build tag: gcp_kms. This file is excluded from the default build so
// the kms module compiles with no cloud SDK dependency.
package gcp

import (
	"context"
	"encoding/pem"
	"fmt"
	"sync"

	gcpkms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/bperin/trust/kms"
	"github.com/bperin/trust/kms/der"

	"github.com/bperin/trust/trust/crypto/secp256k1"
)

// GCPSigner signs digests with a secp256k1 key held in GCP KMS. It
// implements [kms.RemoteSigner]. The struct holds only a key name and
// a GCP KMS client — no private key material.
type GCPSigner struct {
	// keyName is the GCP KMS key resource name, e.g.
	// "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1".
	// It is a reference, never key material.
	keyName string

	// client is the GCP KMS KeyManagementClient used for AsymmetricSign
	// and GetPublicKey calls. The caller constructs and configures it.
	client *gcpkms.KeyManagementClient

	// pub caches the secp256k1 public key fetched from GCP KMS. It is
	// populated lazily on first PublicKey or EVM-path Sign call.
	pubOnce sync.Once
	pub     *secp256k1.PublicKey
	pubErr  error
}

// NewGCPSigner returns a GCPSigner for the given GCP KMS key name and
// client. The client must be configured with credentials sufficient
// to call AsymmetricSign and GetPublicKey on the key. No key material
// is stored — only the key name reference.
func NewGCPSigner(keyName string, client *gcpkms.KeyManagementClient) *GCPSigner {
	return &GCPSigner{keyName: keyName, client: client}
}

// Sign signs a 32-byte pre-computed digest with the GCP KMS key. The
// SignOptions.Path field selects the output wire format:
//
//   - kms.SignPathJOSE: returns 64-byte r||s.
//   - kms.SignPathEVM:  returns 65-byte r||s||v, where v is the
//     [SEC 1 v2] §4.3.3 recovery id.
//
// GCP KMS AsymmetricSign is called with a SHA-256 digest wrapper. The
// DER response is parsed via der.ParseECDSASignature and normalized to
// low-s via der.NormalizeLowS. For the EVM path the recovery id is
// computed via kms.ComputeRecoveryID on the normalized signature.
func (s *GCPSigner) Sign(ctx context.Context, digest []byte, opts kms.SignOptions) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("gcp: digest must be 32 bytes, got %d", len(digest))
	}

	resp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: s.keyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: digest},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("gcp: KMS AsymmetricSign failed: %w", err)
	}

	r, sBytes, err := der.ParseECDSASignature(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("gcp: parse DER signature: %w", err)
	}

	sNorm, flipped := der.NormalizeLowS(sBytes)

	// Build the 64-byte r||s. Left-pad r and s to 32 bytes each —
	// DER integers may be shorter than 32 bytes when leading bytes are
	// zero.
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
			return nil, fmt.Errorf("gcp: %w", err)
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
		return nil, fmt.Errorf("gcp: unknown sign path %d", opts.Path)
	}
}

// PublicKey returns the secp256k1 public key for the GCP KMS key,
// fetched via GetPublicKey and cached. The public key is required to
// compute the recovery id for the EVM path.
func (s *GCPSigner) PublicKey(ctx context.Context) (*secp256k1.PublicKey, error) {
	s.pubOnce.Do(func() {
		s.pubErr = s.loadPublicKey(ctx)
	})
	if s.pubErr != nil {
		return nil, s.pubErr
	}
	return s.pub, nil
}

// loadPublicKey fetches the public key PEM from GCP KMS, decodes it to
// DER, and parses it. It is called once under pubOnce.
func (s *GCPSigner) loadPublicKey(ctx context.Context) error {
	resp, err := s.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: s.keyName,
	})
	if err != nil {
		return fmt.Errorf("gcp: KMS GetPublicKey failed: %w", err)
	}
	derBytes, err := pemToDER(resp.Pem)
	if err != nil {
		return fmt.Errorf("gcp: decode public key PEM: %w", err)
	}
	pub, err := kms.ParsePublicKeyDER(derBytes)
	if err != nil {
		return fmt.Errorf("gcp: parse public key DER: %w", err)
	}
	s.pub = pub
	return nil
}

// Compile-time interface conformance.
var _ kms.RemoteSigner = (*GCPSigner)(nil)

// pemToDER decodes a PEM-encoded block to its raw DER bytes. GCP KMS
// GetPublicKey returns the public key as a PEM string.
func pemToDER(pemStr string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return block.Bytes, nil
}
