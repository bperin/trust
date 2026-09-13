package identity

import (
	"crypto"
	stded25519 "crypto/ed25519"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bperin/trust/trust/crypto/ecdsa"
	"github.com/bperin/trust/trust/crypto/ed25519"
	"github.com/bperin/trust/trust/crypto/rsa"
	"github.com/bperin/trust/trust/crypto/secp256k1"
	"github.com/bperin/trust/trust/signature"
)

// keygen generates a fresh trust keypair for one algorithm.
type keygen func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey)

// algorithmCases covers all six registered signature algorithms:
// ed25519 (default), secp256k1, ecdsa-p256, ecdsa-p384, rsa-pss, and
// rsa-pkcs1v15.
var algorithmCases = []struct {
	name string
	alg  signature.Algorithm
	gen  keygen
}{
	{"ed25519", signature.AlgorithmEdDSA, func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
		priv, pub, err := ed25519.GenerateKey()
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		return priv, pub
	}},
	{"secp256k1", signature.AlgorithmES256K, func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
		priv, pub, err := secp256k1.GenerateKey()
		if err != nil {
			t.Fatalf("secp256k1.GenerateKey: %v", err)
		}
		return priv, pub
	}},
	{"ecdsa-p256", signature.AlgorithmES256, func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
		priv, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey(P-256): %v", err)
		}
		return priv, pub
	}},
	{"ecdsa-p384", signature.AlgorithmES384, func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
		priv, pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey(P-384): %v", err)
		}
		return priv, pub
	}},
	{"rsa-pss", signature.AlgorithmPS256, func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
		priv, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePSSKey: %v", err)
		}
		return priv, pub
	}},
	{"rsa-pkcs1v15", signature.AlgorithmRS256, func(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
		priv, pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePKCS1Key: %v", err)
		}
		return priv, pub
	}},
}

// newDocument builds an unsigned organization document bound to pub.
func newDocument(t *testing.T, id string, pub crypto.PublicKey) *Organization {
	t.Helper()
	alg, err := signature.AlgorithmForPublicKey(pub)
	if err != nil {
		t.Fatalf("AlgorithmForPublicKey: %v", err)
	}
	return &Organization{
		ID:            id,
		RootPublicKey: pub,
		RootAlgorithm: alg,
	}
}

// TestSignVerifyRoundTrip signs an organization document with each
// root key type and verifies it — the basic produce/consume round
// trip across all six algorithms.
func TestSignVerifyRoundTrip(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			priv, pub := tc.gen(t)
			doc := newDocument(t, "did:example:org-"+tc.name, pub)

			if err := Sign(doc, priv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(doc.Signature) == 0 {
				t.Fatal("Sign: Signature is empty")
			}
			if doc.RootAlgorithm != tc.alg {
				t.Fatalf("Sign: RootAlgorithm = %v, want %v", doc.RootAlgorithm, tc.alg)
			}
			if err := Verify(doc); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

// TestSignVerifyKnownVectorEd25519 anchors the round trip to a known
// Ed25519 key from the standard: the seed derives the RFC's public
// key, a signature over the RFC's empty message reproduces the RFC's
// signature bytes, and a document signed with the same key verifies.
//
// Vector: [RFC 8032] §7.1 Test 1 (empty message).
func TestSignVerifyKnownVectorEd25519(t *testing.T) {
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	wantPub, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	wantSig, err := hex.DecodeString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
		"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	full := stded25519.NewKeyFromSeed(seed)
	priv, err := ed25519.NewPrivateKey(full)
	if err != nil {
		t.Fatalf("ed25519.NewPrivateKey: %v", err)
	}
	pub := priv.Public()
	pubBytes := pub.Bytes()
	if subtle.ConstantTimeCompare(pubBytes[:], wantPub) != 1 {
		t.Fatalf("derived public key = %x, want %x", pubBytes[:], wantPub)
	}
	rfcSig := priv.Sign(nil)
	if subtle.ConstantTimeCompare(rfcSig, wantSig) != 1 {
		t.Fatalf("signature over empty message = %x, want %x", rfcSig, wantSig)
	}

	doc := newDocument(t, "did:example:rfc8032", pub)
	if err := Sign(doc, priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(doc); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestSignRejectsWrongSigner proves Sign refuses a key that does not
// control the bound root: the produced signature would never verify,
// so Sign fails instead of storing it.
func TestSignRejectsWrongSigner(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			_, pub := tc.gen(t)
			otherPriv, _ := tc.gen(t)
			doc := newDocument(t, "did:example:org", pub)

			err := Sign(doc, otherPriv)
			if !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("Sign with wrong key: err = %v, want ErrInvalidSignature", err)
			}
			if len(doc.Signature) != 0 {
				t.Fatal("Sign with wrong key stored a signature")
			}
		})
	}
}

// TestVerifyTamperedDocument modifies a field after signing and
// expects the typed signature error on every algorithm.
func TestVerifyTamperedDocument(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			priv, pub := tc.gen(t)
			doc := newDocument(t, "did:example:org", pub)
			if err := Sign(doc, priv); err != nil {
				t.Fatalf("Sign: %v", err)
			}

			doc.ID = "did:example:org-tampered"
			err := Verify(doc)
			if !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("Verify tampered doc: err = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

// TestVerifyWrongRootKey binds the document to a different root key
// of the same algorithm after signing — verification must fail.
func TestVerifyWrongRootKey(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			priv, pub := tc.gen(t)
			_, otherPub := tc.gen(t)
			doc := newDocument(t, "did:example:org", pub)
			if err := Sign(doc, priv); err != nil {
				t.Fatalf("Sign: %v", err)
			}

			doc.RootPublicKey = otherPub
			if err := Verify(doc); err == nil {
				t.Fatal("Verify with wrong root key: got nil, want error")
			}
		})
	}
}

// TestVerifyStructuralFailures covers nil and incomplete documents.
func TestVerifyStructuralFailures(t *testing.T) {
	priv, pub := algorithmCases[0].gen(t)
	doc := newDocument(t, "did:example:org", pub)
	if err := Sign(doc, priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	t.Run("nil document", func(t *testing.T) {
		if err := Verify(nil); !errors.Is(err, ErrNilDocument) {
			t.Fatalf("Verify(nil): err = %v, want ErrNilDocument", err)
		}
	})
	t.Run("missing root key", func(t *testing.T) {
		d := *doc
		d.RootPublicKey = nil
		if err := Verify(&d); !errors.Is(err, ErrMissingRootKey) {
			t.Fatalf("Verify: err = %v, want ErrMissingRootKey", err)
		}
	})
	t.Run("missing signature", func(t *testing.T) {
		d := *doc
		d.Signature = nil
		if err := Verify(&d); !errors.Is(err, ErrMissingSignature) {
			t.Fatalf("Verify: err = %v, want ErrMissingSignature", err)
		}
	})
	t.Run("algorithm mismatch", func(t *testing.T) {
		d := *doc
		d.RootAlgorithm = signature.AlgorithmES256K
		if err := Verify(&d); !errors.Is(err, ErrAlgorithmMismatch) {
			t.Fatalf("Verify: err = %v, want ErrAlgorithmMismatch", err)
		}
	})
}

// TestApplyRotationRoundTrip rotates the root key on every
// algorithm: the rotated document signed by the new root verifies,
// and the same document fails verification under the old root.
func TestApplyRotationRoundTrip(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			oldPriv, oldPub := tc.gen(t)
			newPriv, newPub := tc.gen(t)

			doc := newDocument(t, "did:example:org", oldPub)
			if err := Sign(doc, oldPriv); err != nil {
				t.Fatalf("Sign: %v", err)
			}

			rot := Rotation{
				Sequence:         1,
				NewRootPublicKey: newPub,
			}
			rotated, err := ApplyRotation(doc, rot, oldPriv)
			if err != nil {
				t.Fatalf("ApplyRotation: %v", err)
			}
			if rotated.Rotation == nil {
				t.Fatal("ApplyRotation: Rotation is nil")
			}
			if len(rotated.Rotation.PreviousRootSignature) == 0 {
				t.Fatal("ApplyRotation: PreviousRootSignature is empty")
			}
			if !publicKeyEqual(rotated.RootPublicKey, newPub) {
				t.Fatal("ApplyRotation: RootPublicKey is not the new root")
			}
			if !publicKeyEqual(rotated.Rotation.PreviousRootPublicKey, oldPub) {
				t.Fatal("ApplyRotation: PreviousRootPublicKey is not the old root")
			}

			// The new root completes the rotation by signing.
			if err := Sign(rotated, newPriv); err != nil {
				t.Fatalf("Sign rotated doc: %v", err)
			}
			if err := Verify(rotated); err != nil {
				t.Fatalf("Verify rotated doc: %v", err)
			}

			// The same document fails under the old root: swap the
			// root binding back and verification rejects it.
			oldDoc := *rotated
			oldDoc.RootPublicKey = oldPub
			oldDoc.RootAlgorithm = tc.alg
			if err := Verify(&oldDoc); err == nil {
				t.Fatal("Verify rotated doc under old root: got nil, want error")
			}
		})
	}
}

// TestApplyRotationCrossAlgorithm rotates between different
// algorithms — an ed25519 root replaced by secp256k1, and an RSA-PSS
// root replaced by ed25519.
func TestApplyRotationCrossAlgorithm(t *testing.T) {
	cases := []struct {
		name   string
		oldGen keygen
		newGen keygen
	}{
		{"ed25519-to-secp256k1", algorithmCases[0].gen, algorithmCases[1].gen},
		{"rsa-pss-to-ed25519", algorithmCases[4].gen, algorithmCases[0].gen},
		{"ecdsa-p256-to-rsa-pkcs1", algorithmCases[2].gen, algorithmCases[5].gen},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldPriv, oldPub := tc.oldGen(t)
			newPriv, newPub := tc.newGen(t)

			doc := newDocument(t, "did:example:org", oldPub)
			if err := Sign(doc, oldPriv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			rotated, err := ApplyRotation(doc, Rotation{Sequence: 1, NewRootPublicKey: newPub}, oldPriv)
			if err != nil {
				t.Fatalf("ApplyRotation: %v", err)
			}
			if err := Sign(rotated, newPriv); err != nil {
				t.Fatalf("Sign rotated doc: %v", err)
			}
			if err := Verify(rotated); err != nil {
				t.Fatalf("Verify rotated doc: %v", err)
			}
		})
	}
}

// TestApplyRotationWrongSigner proves a rotation signed by a key
// that is not the current root is rejected — both a different key of
// the same algorithm and a key of a different algorithm.
func TestApplyRotationWrongSigner(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name+" same-alg impostor", func(t *testing.T) {
			oldPriv, oldPub := tc.gen(t)
			impostorPriv, _ := tc.gen(t)
			_, newPub := tc.gen(t)

			doc := newDocument(t, "did:example:org", oldPub)
			if err := Sign(doc, oldPriv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			_, err := ApplyRotation(doc, Rotation{Sequence: 1, NewRootPublicKey: newPub}, impostorPriv)
			if !errors.Is(err, ErrRotationUnauthorized) {
				t.Fatalf("ApplyRotation with impostor: err = %v, want ErrRotationUnauthorized", err)
			}
		})
	}

	t.Run("wrong algorithm signer", func(t *testing.T) {
		edPriv, edPub := algorithmCases[0].gen(t)
		rsaPriv, _ := algorithmCases[4].gen(t)
		_, newPub := algorithmCases[0].gen(t)

		doc := newDocument(t, "did:example:org", edPub)
		if err := Sign(doc, edPriv); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if _, err := ApplyRotation(doc, Rotation{Sequence: 1, NewRootPublicKey: newPub}, rsaPriv); err == nil {
			t.Fatal("ApplyRotation with RSA signer on ed25519 doc: got nil, want error")
		}
	})
}

// TestApplyRotationNonMonotonic proves sequence numbers must
// strictly increase: zero on a first rotation, and equal-or-lower on
// a subsequent rotation, both fail.
func TestApplyRotationNonMonotonic(t *testing.T) {
	gen := algorithmCases[0].gen
	oldPriv, oldPub := gen(t)
	priv2, pub2 := gen(t)
	priv3, pub3 := gen(t)

	doc := newDocument(t, "did:example:org", oldPub)
	if err := Sign(doc, oldPriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	t.Run("sequence zero", func(t *testing.T) {
		_, err := ApplyRotation(doc, Rotation{Sequence: 0, NewRootPublicKey: pub2}, oldPriv)
		if !errors.Is(err, ErrRotationSequence) {
			t.Fatalf("ApplyRotation seq 0: err = %v, want ErrRotationSequence", err)
		}
	})

	rotated, err := ApplyRotation(doc, Rotation{Sequence: 1, NewRootPublicKey: pub2}, oldPriv)
	if err != nil {
		t.Fatalf("ApplyRotation seq 1: %v", err)
	}
	if err := Sign(rotated, priv2); err != nil {
		t.Fatalf("Sign rotated doc: %v", err)
	}

	for _, seq := range []uint64{0, 1} {
		_, err := ApplyRotation(rotated, Rotation{Sequence: seq, NewRootPublicKey: pub3}, priv2)
		if !errors.Is(err, ErrRotationSequence) {
			t.Fatalf("ApplyRotation seq %d after seq 1: err = %v, want ErrRotationSequence", seq, err)
		}
	}

	// A strictly greater sequence succeeds.
	second, err := ApplyRotation(rotated, Rotation{Sequence: 2, NewRootPublicKey: pub3}, priv2)
	if err != nil {
		t.Fatalf("ApplyRotation seq 2: %v", err)
	}
	if err := Sign(second, priv3); err != nil {
		t.Fatalf("Sign second rotation: %v", err)
	}
	if err := Verify(second); err != nil {
		t.Fatalf("Verify second rotation: %v", err)
	}
}

// TestVerifyTamperedRotation modifies the rotation record after the
// rotated document was signed — both the embedded signature and the
// rotation checks must reject it.
func TestVerifyTamperedRotation(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			oldPriv, oldPub := tc.gen(t)
			newPriv, newPub := tc.gen(t)
			_, otherPub := tc.gen(t)

			doc := newDocument(t, "did:example:org", oldPub)
			if err := Sign(doc, oldPriv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			rotated, err := ApplyRotation(doc, Rotation{Sequence: 1, NewRootPublicKey: newPub}, oldPriv)
			if err != nil {
				t.Fatalf("ApplyRotation: %v", err)
			}
			if err := Sign(rotated, newPriv); err != nil {
				t.Fatalf("Sign rotated doc: %v", err)
			}

			t.Run("sequence bumped", func(t *testing.T) {
				d := *rotated
				r := *d.Rotation
				r.Sequence = 99
				d.Rotation = &r
				if err := Verify(&d); err == nil {
					t.Fatal("Verify with tampered sequence: got nil, want error")
				}
			})
			t.Run("new root swapped", func(t *testing.T) {
				d := *rotated
				r := *d.Rotation
				r.NewRootPublicKey = otherPub
				d.Rotation = &r
				if err := Verify(&d); err == nil {
					t.Fatal("Verify with swapped new root: got nil, want error")
				}
			})
			t.Run("prior root signature forged by wrong key", func(t *testing.T) {
				// Forge a rotation: the declared prior root is the
				// real old root, but the signature was made by an
				// unrelated key — verification of
				// PreviousRootSignature must fail.
				forged, err := ApplyRotation(doc, Rotation{Sequence: 1, NewRootPublicKey: newPub}, oldPriv)
				if err != nil {
					t.Fatalf("ApplyRotation: %v", err)
				}
				r := *forged.Rotation
				wrongPriv, _ := tc.gen(t)
				rh, err := rotationHash(&r)
				if err != nil {
					t.Fatalf("rotationHash: %v", err)
				}
				forgedSig, err := signature.Sign(tc.alg, wrongPriv, rh[:])
				if err != nil {
					t.Fatalf("signature.Sign: %v", err)
				}
				r.PreviousRootSignature = forgedSig
				forged.Rotation = &r
				if err := Sign(forged, newPriv); err != nil {
					t.Fatalf("Sign forged doc: %v", err)
				}
				err = Verify(forged)
				if !errors.Is(err, ErrRotationUnauthorized) {
					t.Fatalf("Verify forged rotation: err = %v, want ErrRotationUnauthorized", err)
				}
			})
			t.Run("sequence zero in record", func(t *testing.T) {
				// Bypass the doc signature check by re-signing the
				// tampered document with the new root.
				d := *rotated
				r := *d.Rotation
				r.Sequence = 0
				d.Rotation = &r
				if err := Sign(&d, newPriv); err != nil {
					t.Fatalf("Sign tampered doc: %v", err)
				}
				err := Verify(&d)
				if !errors.Is(err, ErrRotationSequence) {
					t.Fatalf("Verify seq-0 rotation: err = %v, want ErrRotationSequence", err)
				}
			})
		})
	}
}

// TestVerifyRotationMissingFields covers rotation records missing
// required keys — re-signed by the new root so the document
// signature itself is valid.
func TestVerifyRotationMissingFields(t *testing.T) {
	oldPriv, oldPub := algorithmCases[0].gen(t)
	newPriv, newPub := algorithmCases[0].gen(t)

	doc := newDocument(t, "did:example:org", oldPub)
	if err := Sign(doc, oldPriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	rotated, err := ApplyRotation(doc, Rotation{Sequence: 1, NewRootPublicKey: newPub}, oldPriv)
	if err != nil {
		t.Fatalf("ApplyRotation: %v", err)
	}
	if err := Sign(rotated, newPriv); err != nil {
		t.Fatalf("Sign rotated doc: %v", err)
	}

	t.Run("missing prior root", func(t *testing.T) {
		// No re-sign needed: the rotation's structural check runs
		// before canonicalization, which would fail on the nil key.
		d := *rotated
		r := *d.Rotation
		r.PreviousRootPublicKey = nil
		d.Rotation = &r
		if err := Verify(&d); !errors.Is(err, ErrMissingRootKey) {
			t.Fatalf("Verify: err = %v, want ErrMissingRootKey", err)
		}
	})
	t.Run("missing prior signature", func(t *testing.T) {
		d := *rotated
		r := *d.Rotation
		r.PreviousRootSignature = nil
		d.Rotation = &r
		if err := Sign(&d, newPriv); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := Verify(&d); !errors.Is(err, ErrRotationUnauthorized) {
			t.Fatalf("Verify: err = %v, want ErrRotationUnauthorized", err)
		}
	})
}

// TestCanonicalHashDeterministic proves the canonical hash is stable
// for a fixed document and changes when any field changes.
func TestCanonicalHashDeterministic(t *testing.T) {
	_, pub := algorithmCases[0].gen(t)
	doc := newDocument(t, "did:example:org", pub)

	h1, err := CanonicalHash(doc)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	h2, err := CanonicalHash(doc)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	if subtle.ConstantTimeCompare(h1[:], h2[:]) != 1 {
		t.Fatalf("CanonicalHash not deterministic: %x != %x", h1, h2)
	}

	doc.ID = "did:example:other"
	h3, err := CanonicalHash(doc)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	if subtle.ConstantTimeCompare(h1[:], h3[:]) == 1 {
		t.Fatal("CanonicalHash did not change after ID change")
	}
}
