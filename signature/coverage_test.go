package signature

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"
	"testing"

	"github.com/bperin/trust/crypto/secp256k1"
)

// secp256k1OrderN is the secp256k1 group order n ([SEC 2 v2] §2.4.1), used to
// build high-s and low-s test values.
var secp256k1OrderN = mustBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

// mustBigInt parses a hexadecimal big integer, panicking on a bad literal.
func mustBigInt(hexDigits string) *big.Int {
	n, ok := new(big.Int).SetString(hexDigits, 16)
	if !ok {
		panic("signature: invalid hex constant " + hexDigits)
	}
	return n
}

// foreignKeyAlg returns an algorithm whose public-key Go type differs from
// alg's, so a wrong-key-type call exercises the structural error path.
func foreignKeyAlg(alg Algorithm) Algorithm {
	if alg == AlgorithmEdDSA {
		return AlgorithmES256
	}
	return AlgorithmEdDSA
}

// otherRegisteredAlg returns a registered algorithm distinct from alg.
func otherRegisteredAlg(alg Algorithm) Algorithm {
	for _, candidate := range allAlgorithms() {
		if candidate != alg {
			return candidate
		}
	}
	panic("signature: fewer than two registered algorithms")
}

// coverageMessage returns the message an algorithm case is exercised with.
func coverageMessage(alg Algorithm) []byte {
	return []byte("trust signature dispatch coverage: " + alg.JOSE())
}

func TestVerifyCoverage(t *testing.T) {
	t.Parallel()

	for _, alg := range allAlgorithms() {
		t.Run(alg.JOSE(), func(t *testing.T) {
			t.Parallel()

			kp := generateKeyPair(t, alg)
			foreign := generateKeyPair(t, foreignKeyAlg(alg))
			msg := coverageMessage(alg)

			sig, err := Sign(alg, kp.priv, msg)
			if err != nil {
				t.Fatalf("Sign(%s): %v", alg.JOSE(), err)
			}
			if len(sig) == 0 {
				t.Fatalf("Sign(%s): returned an empty signature", alg.JOSE())
			}

			t.Run("valid_signature", func(t *testing.T) {
				valid, err := Verify(alg, kp.pub, sig, msg)
				if err != nil || !valid {
					t.Fatalf("Verify(%s) = (%v, %v), want (true, nil)", alg.JOSE(), valid, err)
				}
			})

			t.Run("tampered_signature", func(t *testing.T) {
				bad := append([]byte{}, sig...)
				bad[len(bad)-1] ^= 0xFF
				assertRejected(t, alg, kp.pub, bad, msg)
			})

			t.Run("tampered_message", func(t *testing.T) {
				bad := append([]byte{}, msg...)
				bad[0] ^= 0xFF
				assertRejected(t, alg, kp.pub, sig, bad)
			})

			t.Run("empty_signature", func(t *testing.T) {
				assertRejected(t, alg, kp.pub, nil, msg)
			})

			t.Run("truncated_signature", func(t *testing.T) {
				assertRejected(t, alg, kp.pub, sig[:len(sig)/2], msg)
			})

			t.Run("empty_message", func(t *testing.T) {
				emptySig, err := Sign(alg, kp.priv, nil)
				if err != nil {
					t.Fatalf("Sign(%s, nil msg): %v", alg.JOSE(), err)
				}
				valid, err := Verify(alg, kp.pub, emptySig, nil)
				if err != nil || !valid {
					t.Fatalf("Verify(%s) over an empty message = (%v, %v), want (true, nil)",
						alg.JOSE(), valid, err)
				}
				if subtle.ConstantTimeCompare(emptySig, sig) == 1 {
					t.Errorf("signature over an empty message equals the signature over %q", msg)
				}
			})

			t.Run("one_byte_message", func(t *testing.T) {
				oneByte := []byte{0x2A}
				shortSig, err := Sign(alg, kp.priv, oneByte)
				if err != nil {
					t.Fatalf("Sign(%s, 1-byte msg): %v", alg.JOSE(), err)
				}
				valid, err := Verify(alg, kp.pub, shortSig, oneByte)
				if err != nil || !valid {
					t.Fatalf("Verify(%s) over a 1-byte message = (%v, %v), want (true, nil)",
						alg.JOSE(), valid, err)
				}
			})

			t.Run("wrong_key_type", func(t *testing.T) {
				valid, err := Verify(alg, foreign.pub, sig, msg)
				if valid {
					t.Errorf("Verify(%s) with a %T key returned true, want false", alg.JOSE(), foreign.pub)
				}
				if err == nil {
					t.Fatalf("Verify(%s) with a %T key: got (false, nil), want a structural error",
						alg.JOSE(), foreign.pub)
				}
				var mismatch *ErrAlgMismatch
				if !errors.As(err, &mismatch) {
					t.Fatalf("Verify(%s) with a %T key: err = %v, want *ErrAlgMismatch", alg.JOSE(), foreign.pub, err)
				}
			})

			t.Run("wrong_declared_algorithm", func(t *testing.T) {
				other := otherRegisteredAlg(alg)
				valid, err := Verify(other, kp.pub, sig, msg)
				if valid {
					t.Errorf("Verify(%s) over a %s signature returned true, want false", other.JOSE(), alg.JOSE())
				}
				if err == nil {
					t.Errorf("Verify(%s) over a %s signature: got (false, nil), want a structural error",
						other.JOSE(), alg.JOSE())
				}
			})
		})
	}
}

// assertRejected requires the cryptographic-rejection contract: invalid input
// yields (false, nil), never a silent accept.
func assertRejected(t *testing.T, alg Algorithm, key crypto.PublicKey, sig, msg []byte) {
	t.Helper()
	valid, err := Verify(alg, key, sig, msg)
	if valid {
		t.Errorf("Verify(%s) = true for a rejected input, want false [sig=%d bytes msg=%d bytes]",
			alg.JOSE(), len(sig), len(msg))
	}
	if err != nil {
		t.Errorf("Verify(%s) = (false, %v), want the (false, nil) contract for an invalid signature",
			alg.JOSE(), err)
	}
}

// TestES256KLowS verifies the ES256K wire format rejects high-s and accepts
// low-s per [EIP-2], including the mathematically valid malleated companion.
func TestES256KLowS(t *testing.T) {
	t.Parallel()

	msg := []byte("es256k low-s enforcement")
	priv, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("secp256k1.GenerateKey: %v", err)
	}

	sig, err := Sign(AlgorithmES256K, priv, msg)
	if err != nil {
		t.Fatalf("Sign(ES256K): %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want the 64-byte r||s form", len(sig))
	}

	halfN := new(big.Int).Rsh(secp256k1OrderN, 1)
	tests := []struct {
		name      string
		s         *big.Int
		wantValid bool
	}{
		{"registered_low_s", new(big.Int).SetBytes(sig[32:]), true},
		{"malleated_high_s", new(big.Int).Sub(secp256k1OrderN, new(big.Int).SetBytes(sig[32:])), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sBytes := tc.s.Bytes()
			if len(sBytes) > 32 {
				t.Fatalf("s width = %d bytes, want at most 32", len(sBytes))
			}
			candidate := make([]byte, 64)
			copy(candidate[:32], sig[:32])
			copy(candidate[64-len(sBytes):], sBytes)

			if isHigh := new(big.Int).SetBytes(candidate[32:]).Cmp(halfN) > 0; isHigh == tc.wantValid {
				t.Fatalf("case classification is inconsistent: isHigh=%v, wantValid=%v", isHigh, tc.wantValid)
			}

			valid, err := Verify(AlgorithmES256K, pub, candidate, msg)
			if err != nil {
				t.Fatalf("Verify(ES256K): got error %v, want nil", err)
			}
			if valid != tc.wantValid {
				t.Errorf("Verify(ES256K) with s=%x = %v, want %v", candidate[32:], valid, tc.wantValid)
			}
		})
	}
}

// TestES256KRecoverableSignature verifies the 65-byte r||s||v form used by the
// EVM path recovers the expected key and that a wrong recovery id does not.
func TestES256KRecoverableSignature(t *testing.T) {
	t.Parallel()

	msg := []byte("es256k recovery id binding")
	priv, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("secp256k1.GenerateKey: %v", err)
	}
	digest := sha256.Sum256(msg)

	sig, recID, err := priv.SignRecoverable(digest[:])
	if err != nil {
		t.Fatalf("SignRecoverable: %v", err)
	}
	if recID > 3 {
		t.Fatalf("recovery id = %d, want 0-3", recID)
	}

	valid, err := Verify(AlgorithmES256K, pub, sig, msg)
	if err != nil || !valid {
		t.Fatalf("Verify(ES256K) on the r||s half = (%v, %v), want (true, nil)", valid, err)
	}

	sig65 := make([]byte, 65)
	copy(sig65[:64], sig)
	sig65[64] = recID

	t.Run("recovers_expected_key", func(t *testing.T) {
		recovered, err := secp256k1.RecoverPubKey(sig65[:64], digest[:], sig65[64])
		if err != nil {
			t.Fatalf("RecoverPubKey(v=%d): %v", sig65[64], err)
		}
		got, want := recovered.Bytes(), pub.Bytes()
		if subtle.ConstantTimeCompare(got, want) != 1 {
			t.Errorf("recovered key = %x, want %x", got, want)
		}
	})

	t.Run("dispatch_sign_matches_recoverable_sign", func(t *testing.T) {
		plain, err := Sign(AlgorithmES256K, priv, msg)
		if err != nil {
			t.Fatalf("Sign(ES256K): %v", err)
		}
		if subtle.ConstantTimeCompare(plain, sig[:64]) != 1 {
			t.Errorf("dispatch Sign produced %x, recoverable Sign produced %x", plain, sig[:64])
		}
	})

	t.Run("trial_recovery_finds_only_one_id", func(t *testing.T) {
		var matched []byte
		for v := byte(0); v < 4; v++ {
			recovered, err := secp256k1.RecoverPubKey(sig, digest[:], v)
			if err == nil && recovered.Equal(pub) {
				matched = append(matched, v)
			}
		}
		if len(matched) != 1 || matched[0] != recID {
			t.Errorf("recovery ids matching the signing key = %v, want exactly [%d]", matched, recID)
		}
	})

	t.Run("wrong_recovery_id_recovers_other_key", func(t *testing.T) {
		for v := byte(0); v < 4; v++ {
			if v == recID {
				continue
			}
			recovered, err := secp256k1.RecoverPubKey(sig, digest[:], v)
			if err == nil && recovered.Equal(pub) {
				t.Errorf("recovery id %d recovered the signing key, want a different key (only id %d is valid)",
					v, recID)
			}
		}
	})

	t.Run("out_of_range_recovery_id", func(t *testing.T) {
		if _, err := secp256k1.RecoverPubKey(sig, digest[:], 4); err == nil {
			t.Errorf("RecoverPubKey(v=4): got nil error, want rejection of an out-of-range recovery id")
		}
	})
}
