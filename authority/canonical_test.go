package authority

import (
	"errors"
	"testing"

	"github.com/bperin/trust/signature"
)

func TestCanonicalHash_Deterministic(t *testing.T) {
	t.Parallel()

	// Two logically identical authorities built independently must
	// yield the same canonical hash.
	a := testAuthority()
	b := testAuthority()

	ha, err := CanonicalHash(a)
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	hb, err := CanonicalHash(b)
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if ha != hb {
		t.Fatalf("determinism: got %x and %x for identical authorities", ha, hb)
	}
}

func TestCanonicalHash_SignatureExcluded(t *testing.T) {
	t.Parallel()

	base := testAuthority()
	base.Proof.Signature = nil
	hBase, err := CanonicalHash(base)
	if err != nil {
		t.Fatalf("hash base: %v", err)
	}

	cases := []struct {
		name string
		sig  []byte
	}{
		{"empty signature", []byte{}},
		{"short signature", []byte{0x01}},
		{"long signature", bytes64(0xAB)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := testAuthority()
			a.Proof.Signature = tc.sig
			got, err := CanonicalHash(a)
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			if got != hBase {
				t.Fatalf("signature %x changed hash: got %x, want %x", tc.sig, got, hBase)
			}
			// The caller's authority must not be mutated.
			if len(a.Proof.Signature) != len(tc.sig) {
				t.Fatalf("CanonicalHash mutated caller signature: len got %d, want %d",
					len(a.Proof.Signature), len(tc.sig))
			}
		})
	}
}

func bytes64(v byte) []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = v
	}
	return b
}

func TestCanonicalHash_AlgorithmAndKeyIDIncluded(t *testing.T) {
	t.Parallel()

	base := testAuthority()
	hBase, err := CanonicalHash(base)
	if err != nil {
		t.Fatalf("hash base: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Authority)
	}{
		{"different algorithm", func(a *Authority) { a.Proof.Algorithm = signature.AlgorithmES256 }},
		{"different key id", func(a *Authority) { a.Proof.KeyID = "key-2" }},
		{"zero algorithm", func(a *Authority) { a.Proof.Algorithm = 0 }},
		{"empty key id", func(a *Authority) { a.Proof.KeyID = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := testAuthority()
			tc.mutate(a)
			got, err := CanonicalHash(a)
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			if got == hBase {
				t.Fatalf("mutation did not change hash: got %x, want different from %x", got, hBase)
			}
		})
	}
}

func TestCanonicalHash_RootVsDelegated(t *testing.T) {
	t.Parallel()

	root := testAuthority()
	root.Parent = nil

	parent := "deadbeef"
	delegated := testAuthority()
	delegated.Parent = &parent

	hRoot, err := CanonicalHash(root)
	if err != nil {
		t.Fatalf("hash root: %v", err)
	}
	hDelegated, err := CanonicalHash(delegated)
	if err != nil {
		t.Fatalf("hash delegated: %v", err)
	}
	if hRoot == hDelegated {
		t.Fatal("root and delegated authorities produced the same hash")
	}
}

func TestCanonicalHash_Nil(t *testing.T) {
	t.Parallel()

	got, err := CanonicalHash(nil)
	if !errors.Is(err, ErrNilAuthority) {
		t.Fatalf("CanonicalHash(nil): got err %v, want %v", err, ErrNilAuthority)
	}
	if got != [32]byte{} {
		t.Fatalf("CanonicalHash(nil): got hash %x, want zero", got)
	}
}
