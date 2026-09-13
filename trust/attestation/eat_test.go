package attestation

import (
	"crypto"
	"crypto/elliptic"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/bperin/trust/trust/credential"
	"github.com/bperin/trust/trust/crypto/ecdsa"
	"github.com/bperin/trust/trust/crypto/ed25519"
	"github.com/bperin/trust/trust/crypto/rsa"
	"github.com/bperin/trust/trust/crypto/secp256k1"
	"github.com/bperin/trust/trust/evidence"
	"github.com/bperin/trust/trust/signature"
)

// attKeyPair is a generated trust keypair for one algorithm.
type attKeyPair struct {
	priv crypto.PrivateKey
	pub  crypto.PublicKey
}

// attGenPair generates a fresh trust keypair for one registered
// algorithm.
func attGenPair(alg signature.Algorithm) (attKeyPair, error) {
	switch alg {
	case signature.AlgorithmEdDSA:
		priv, pub, err := ed25519.GenerateKey()
		return attKeyPair{priv, pub}, err
	case signature.AlgorithmES256K:
		priv, pub, err := secp256k1.GenerateKey()
		return attKeyPair{priv, pub}, err
	case signature.AlgorithmES256:
		priv, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
		return attKeyPair{priv, pub}, err
	case signature.AlgorithmES384:
		priv, pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
		return attKeyPair{priv, pub}, err
	case signature.AlgorithmPS256:
		priv, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
		return attKeyPair{priv, pub}, err
	case signature.AlgorithmRS256:
		priv, pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
		return attKeyPair{priv, pub}, err
	default:
		return attKeyPair{}, fmt.Errorf("untested algorithm %v", alg)
	}
}

// attAlgorithmCases covers all six registered signature algorithms:
// ed25519 (default), secp256k1, ecdsa-p256, ecdsa-p384, rsa-pss, and
// rsa-pkcs1v15.
var attAlgorithmCases = []struct {
	name string
	alg  signature.Algorithm
}{
	{"ed25519", signature.AlgorithmEdDSA},
	{"secp256k1", signature.AlgorithmES256K},
	{"ecdsa-p256", signature.AlgorithmES256},
	{"ecdsa-p384", signature.AlgorithmES384},
	{"rsa-pss", signature.AlgorithmPS256},
	{"rsa-pkcs1v15", signature.AlgorithmRS256},
}

// attKeyPool holds two pre-generated keypairs per algorithm (leaf +
// spare) so RSA key generation cost is paid once in TestMain rather
// than per test. Keys are shared read-only across tests.
var attKeyPool map[signature.Algorithm][]attKeyPair

func TestMain(m *testing.M) {
	attKeyPool = make(map[signature.Algorithm][]attKeyPair, len(attAlgorithmCases))
	for _, tc := range attAlgorithmCases {
		for i := 0; i < 2; i++ {
			kp, err := attGenPair(tc.alg)
			if err != nil {
				panic(fmt.Sprintf("attGenPair(%s): %v", tc.name, err))
			}
			attKeyPool[tc.alg] = append(attKeyPool[tc.alg], kp)
		}
	}
	os.Exit(m.Run())
}

// Fixed validity windows — deterministic across runs.
var (
	attWinStart = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	attWinEnd   = attWinStart.AddDate(1, 0, 0)
)

// buildAttestation returns a valid unsigned Attestation with authority
// references and evidence. The caller signs it with a leaf key.
func buildAttestation(t *testing.T) *Attestation {
	t.Helper()
	claim := &credential.VersionedClaim{
		Version:   1,
		Schema:    "https://example.com/schemas/product-v1",
		Subject:   "did:example:subject",
		Resource:  "res-a",
		Issuer:    "did:example:claimer",
		IssuedAt:  attWinStart,
		NotBefore: attWinStart,
		NotAfter:  attWinEnd,
		Payload:   map[string]interface{}{"product": "widget", "qty": float64(42)},
		Evidence: []evidence.EvidenceRef{
			{
				Type:        "pdf",
				URI:         "ipfs://QmEvidenceHash",
				ContentHash: evidence.HashContent([]byte("evidence-bytes")),
			},
		},
	}
	authRef, err := credential.CanonicalHash(claim)
	if err != nil {
		t.Fatalf("credential.CanonicalHash: got error %v, want nil", err)
	}
	return &Attestation{
		Claim:               claim,
		Issuer:              "did:example:attester",
		SigningKeyID:        "leaf-key-1",
		SigningKeyVersion:   1,
		AuthorityRef:        authRef,
		DelegationChainHash: authRef,
		Evidence:            claim.Evidence,
		IssuedAt:            attWinStart,
		NotBefore:           attWinStart,
		NotAfter:            attWinEnd,
		Status:              "active",
	}
}

// leafKey returns the first pre-generated leaf keypair for alg.
func leafKey(t *testing.T, alg signature.Algorithm) attKeyPair {
	t.Helper()
	pool := attKeyPool[alg]
	if len(pool) == 0 {
		t.Fatalf("attKeyPool[%v] is empty", alg)
	}
	return pool[0]
}

// wrongAlgorithmKey returns a public key whose algorithm differs from
// alg, so VerifyAttestation reports ErrWrongKey (algorithm-confusion
// defense). It rotates to the next algorithm in attAlgorithmCases.
func wrongAlgorithmKey(t *testing.T, alg signature.Algorithm) crypto.PublicKey {
	t.Helper()
	for i, tc := range attAlgorithmCases {
		if tc.alg == alg {
			next := attAlgorithmCases[(i+1)%len(attAlgorithmCases)]
			return leafKey(t, next.alg).pub
		}
	}
	t.Fatalf("algorithm %v not in attAlgorithmCases", alg)
	return nil
}

// hashEqual reports whether two digests are equal in constant time.
func hashEqual(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// TestAttestationRoundTrip signs an attestation with the leaf key and
// verifies it under every registered algorithm, asserting the
// canonical hash is stable — the identity is independent of the
// Signature field.
func TestAttestationRoundTrip(t *testing.T) {
	t.Parallel()
	for _, tc := range attAlgorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			att := buildAttestation(t)
			kp := leafKey(t, tc.alg)

			if err := SignAttestation(att, kp.priv); err != nil {
				t.Fatalf("SignAttestation: got error %v, want nil", err)
			}
			if att.Algorithm != tc.alg {
				t.Errorf("Algorithm: got %v, want %v", att.Algorithm, tc.alg)
			}
			if len(att.Signature) == 0 {
				t.Fatalf("Signature: got empty, want non-empty")
			}

			// The canonical hash is the unsigned identity: it must not
			// depend on the Signature field. Hash the signed attestation,
			// then hash a copy with the signature stripped — both must
			// agree.
			h1, err := CanonicalHash(att)
			if err != nil {
				t.Fatalf("CanonicalHash signed: got error %v, want nil", err)
			}
			sig := att.Signature
			att.Signature = nil
			h2, err := CanonicalHash(att)
			att.Signature = sig
			if err != nil {
				t.Fatalf("CanonicalHash unsigned: got error %v, want nil", err)
			}
			if !hashEqual(h1, h2) {
				t.Errorf("canonical hash depends on signature: got %x, want %x", h2, h1)
			}

			if err := VerifyAttestation(att, kp.pub); err != nil {
				t.Fatalf("VerifyAttestation: got error %v, want nil", err)
			}
		})
	}
}

// TestAttestationAuthorityAndEvidence confirms an attestation carrying
// authority references and evidence verifies under every algorithm.
func TestAttestationAuthorityAndEvidence(t *testing.T) {
	t.Parallel()
	for _, tc := range attAlgorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			att := buildAttestation(t)
			kp := leafKey(t, tc.alg)

			var zero [32]byte
			if subtle.ConstantTimeCompare(att.AuthorityRef[:], zero[:]) == 1 {
				t.Fatalf("AuthorityRef: got zero, want non-zero")
			}
			if len(att.Evidence) == 0 {
				t.Fatalf("Evidence: got empty, want non-empty")
			}

			if err := SignAttestation(att, kp.priv); err != nil {
				t.Fatalf("SignAttestation: got error %v, want nil", err)
			}
			if err := VerifyAttestation(att, kp.pub); err != nil {
				t.Fatalf("VerifyAttestation: got error %v, want nil", err)
			}
		})
	}
}

// TestAttestationTampered modifies a signed attestation field after
// signing and asserts VerifyAttestation returns ErrTamperedAttestation.
func TestAttestationTampered(t *testing.T) {
	t.Parallel()
	for _, tc := range attAlgorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			att := buildAttestation(t)
			kp := leafKey(t, tc.alg)
			if err := SignAttestation(att, kp.priv); err != nil {
				t.Fatalf("SignAttestation: got error %v, want nil", err)
			}

			// Tamper with the issuer after signing. This changes the
			// canonical hash, so the stored signature no longer matches.
			att.Issuer = "did:example:attacker"

			err := VerifyAttestation(att, kp.pub)
			if !errors.Is(err, ErrTamperedAttestation) {
				t.Errorf("VerifyAttestation tampered: got error %v, want errors.Is(_, ErrTamperedAttestation)", err)
			}
		})
	}
}

// TestAttestationWrongKey verifies with a leaf public key of a
// different algorithm and asserts VerifyAttestation returns ErrWrongKey.
func TestAttestationWrongKey(t *testing.T) {
	t.Parallel()
	for _, tc := range attAlgorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			att := buildAttestation(t)
			kp := leafKey(t, tc.alg)
			if err := SignAttestation(att, kp.priv); err != nil {
				t.Fatalf("SignAttestation: got error %v, want nil", err)
			}

			wrongPub := wrongAlgorithmKey(t, tc.alg)
			err := VerifyAttestation(att, wrongPub)
			if !errors.Is(err, ErrWrongKey) {
				t.Errorf("VerifyAttestation wrong key: got error %v, want errors.Is(_, ErrWrongKey)", err)
			}
		})
	}
}

// TestAttestationMissingAuthorityRef signs an attestation whose
// AuthorityRef is the zero value and asserts VerifyAttestation returns
// ErrMissingAuthorityRef.
func TestAttestationMissingAuthorityRef(t *testing.T) {
	t.Parallel()
	for _, tc := range attAlgorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			att := buildAttestation(t)
			att.AuthorityRef = [32]byte{}
			kp := leafKey(t, tc.alg)
			if err := SignAttestation(att, kp.priv); err != nil {
				t.Fatalf("SignAttestation: got error %v, want nil", err)
			}

			err := VerifyAttestation(att, kp.pub)
			if !errors.Is(err, ErrMissingAuthorityRef) {
				t.Errorf("VerifyAttestation zero authority ref: got error %v, want errors.Is(_, ErrMissingAuthorityRef)", err)
			}
		})
	}
}

// TestAttestationCanonicalHashDeterminism asserts two independently
// constructed attestations with identical content produce the same
// canonical hash across two runs, under every algorithm's key. Both
// are signed under the same algorithm so the Algorithm field matches;
// the signature is excluded from the canonical hash, so differing
// signatures (randomized algorithms) do not affect the identity.
func TestAttestationCanonicalHashDeterminism(t *testing.T) {
	t.Parallel()
	for _, tc := range attAlgorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			first := buildAttestation(t)
			second := buildAttestation(t)

			// Sign both under the same algorithm so the Algorithm
			// field — part of the signed content — matches.
			if err := SignAttestation(first, leafKey(t, tc.alg).priv); err != nil {
				t.Fatalf("SignAttestation first: got error %v, want nil", err)
			}
			if err := SignAttestation(second, leafKey(t, tc.alg).priv); err != nil {
				t.Fatalf("SignAttestation second: got error %v, want nil", err)
			}

			h1, err := CanonicalHash(first)
			if err != nil {
				t.Fatalf("CanonicalHash first: got error %v, want nil", err)
			}
			h2, err := CanonicalHash(second)
			if err != nil {
				t.Fatalf("CanonicalHash second: got error %v, want nil", err)
			}
			if !hashEqual(h1, h2) {
				t.Errorf("canonical hash not deterministic: got %x, want %x", h2, h1)
			}

			// Re-hashing the same attestation must yield the same
			// identity — the hash is a pure function of the content.
			h3, err := CanonicalHash(first)
			if err != nil {
				t.Fatalf("CanonicalHash repeat: got error %v, want nil", err)
			}
			if !hashEqual(h1, h3) {
				t.Errorf("canonical hash not stable on re-hash: got %x, want %x", h3, h1)
			}
		})
	}
}
