package kms

import (
	"crypto"
	"crypto/elliptic"
	"testing"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/kms/der"
	"github.com/bperin/trust/signature"
)

// kmsVector names the committed testdata files carrying one message, one
// provider-produced signature, and one DER public key.
type kmsVector struct {
	name     string
	alg      signature.Algorithm
	msgFile  string
	sigFile  string
	pubFile  string
	rawRS    bool
	wrongAlg signature.Algorithm
}

// committedKMSVectors are the recorded Cloud KMS pairs plus the synthetic
// P-256 and secp256k1 pairs; see testdata/VECTORS.md for provenance.
func committedKMSVectors() []kmsVector {
	return []kmsVector{
		{
			name:     "ed25519_raw64_over_unhashed_message",
			alg:      signature.AlgorithmEdDSA,
			msgFile:  "kms_ed25519_msg",
			sigFile:  "kms_ed25519_signature",
			pubFile:  "kms_ed25519_pubkey",
			wrongAlg: signature.AlgorithmES256,
		},
		{
			name:     "p384_der_over_sha384",
			alg:      signature.AlgorithmES384,
			msgFile:  "kms_p384_msg",
			sigFile:  "kms_p384_signature",
			pubFile:  "kms_p384_der_pubkey",
			wrongAlg: signature.AlgorithmES256,
		},
		{
			name:     "p256_der_over_sha256",
			alg:      signature.AlgorithmES256,
			msgFile:  "kms_p256_msg",
			sigFile:  "kms_p256_signature",
			pubFile:  "kms_p256_der_pubkey",
			wrongAlg: signature.AlgorithmES384,
		},
		{
			name:     "secp256k1_der_converted_to_raw_rs",
			alg:      signature.AlgorithmES256K,
			msgFile:  "kms_es256k_msg",
			sigFile:  "kms_es256k_signature",
			pubFile:  "kms_es256k_der_pubkey",
			rawRS:    true,
			wrongAlg: signature.AlgorithmES256,
		},
	}
}

// vectorWireFormat returns the message and the signature in the exact wire
// format the algorithm accepts, converting DER to r||s where required.
func vectorWireFormat(t *testing.T, v kmsVector) (msg, sig []byte) {
	t.Helper()
	msg = readVector(t, v.msgFile)
	sig = readVector(t, v.sigFile)
	if !v.rawRS {
		return msg, sig
	}

	r, s, err := der.ParseECDSASignature(sig)
	if err != nil {
		t.Fatalf("der.ParseECDSASignature(testdata/%s): %v", v.sigFile, err)
	}
	normalized, flipped := der.NormalizeLowS(s)
	if flipped {
		t.Errorf("recorded secp256k1 vector needed low-s normalization; the committed vector must already be low-s")
	}
	raw := make([]byte, 64)
	if len(r) > 32 || len(normalized) > 32 {
		t.Fatalf("scalars exceed the 32-byte width: len(r)=%d, len(s)=%d", len(r), len(normalized))
	}
	copy(raw[32-len(r):32], r)
	copy(raw[64-len(normalized):64], normalized)
	return msg, raw
}

// vectorKey parses the committed public key and asserts it binds to the
// algorithm the vector declares.
func vectorKey(t *testing.T, v kmsVector) crypto.PublicKey {
	t.Helper()
	key, err := ParsePublicKeyDER(readVector(t, v.pubFile))
	if err != nil {
		t.Fatalf("ParsePublicKeyDER(testdata/%s): %v", v.pubFile, err)
	}
	bound, err := signature.AlgorithmForPublicKey(key)
	if err != nil {
		t.Fatalf("AlgorithmForPublicKey(%T): %v", key, err)
	}
	if bound != v.alg {
		t.Fatalf("key binds to %s, vector declares %s", bound.JOSE(), v.alg.JOSE())
	}
	return key
}

// unrelatedKey generates a fresh public key of the vector's algorithm.
func unrelatedKey(t *testing.T, alg signature.Algorithm) crypto.PublicKey {
	t.Helper()
	switch alg {
	case signature.AlgorithmEdDSA:
		_, pub, err := ed25519.GenerateKey()
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		return pub
	case signature.AlgorithmES256:
		_, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey(P-256): %v", err)
		}
		return pub
	case signature.AlgorithmES384:
		_, pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey(P-384): %v", err)
		}
		return pub
	case signature.AlgorithmES256K:
		_, pub, err := secp256k1.GenerateKey()
		if err != nil {
			t.Fatalf("secp256k1.GenerateKey: %v", err)
		}
		return pub
	default:
		t.Fatalf("no key generator for %s", alg.JOSE())
		return nil
	}
}

func TestVerifyKMSVectors(t *testing.T) {
	t.Parallel()

	for _, v := range committedKMSVectors() {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			msg, sig := vectorWireFormat(t, v)
			key := vectorKey(t, v)

			valid, err := signature.Verify(v.alg, key, sig, msg)
			if err != nil {
				t.Fatalf("Verify(%s): got error %v, want nil", v.alg.JOSE(), err)
			}
			if !valid {
				t.Errorf("Verify(%s) = false for a committed provider vector, want true [msg=%q sig=%d bytes]",
					v.alg.JOSE(), msg, len(sig))
			}

			again, err := signature.Verify(v.alg, key, sig, msg)
			if err != nil || !again {
				t.Errorf("Verify(%s) recheck = (%v, %v), want (true, nil)", v.alg.JOSE(), again, err)
			}
		})
	}
}

func TestVerifyKMSVectors_Negatives(t *testing.T) {
	t.Parallel()

	for _, v := range committedKMSVectors() {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			msg, sig := vectorWireFormat(t, v)
			key := vectorKey(t, v)
			providerSig := readVector(t, v.sigFile)

			tamperedSig := append([]byte{}, sig...)
			tamperedSig[len(tamperedSig)-1] ^= 0xFF
			tamperedMsg := append([]byte{}, msg...)
			tamperedMsg[0] ^= 0xFF

			tests := []struct {
				name    string
				alg     signature.Algorithm
				key     crypto.PublicKey
				sig     []byte
				msg     []byte
				wantErr bool
			}{
				{"tampered_signature", v.alg, key, tamperedSig, msg, false},
				{"tampered_message", v.alg, key, sig, tamperedMsg, false},
				{"empty_message", v.alg, key, sig, nil, false},
				{"truncated_signature", v.alg, key, providerSig[:len(providerSig)/2], msg, false},
				{"wrong_key", v.alg, unrelatedKey(t, v.alg), sig, msg, false},
				{"wrong_declared_algorithm", v.wrongAlg, key, sig, msg, true},
			}

			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					valid, err := signature.Verify(tc.alg, tc.key, tc.sig, tc.msg)
					if valid {
						t.Errorf("Verify(%s under %s) = true, want false", tc.name, tc.alg.JOSE())
					}
					if tc.wantErr && err == nil {
						t.Errorf("Verify(%s under %s): got (false, nil), want a structural error",
							tc.name, tc.alg.JOSE())
					}
					if !tc.wantErr && err != nil {
						t.Errorf("Verify(%s under %s): got error %v, want the (false, nil) contract",
							tc.name, tc.alg.JOSE(), err)
					}
				})
			}
		})
	}
}
