package commitment

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"sync"
	"testing"
)

// splitmix64 is a deterministic PRNG for test permutations — fixed-seed,
// reproducible across runs and processes. math/rand is forbidden; this is
// a pure function of the seed with no global state.
type splitmix64 struct{ s uint64 }

func (r *splitmix64) next() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// permutation returns a deterministic Fisher–Yates shuffle of 0..n-1 driven
// by seed — the same seed always produces the same permutation.
func permutation(n int, seed uint64) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	r := splitmix64{s: seed}
	for i := n - 1; i > 0; i-- {
		j := int(r.next() % uint64(i+1))
		p[i], p[j] = p[j], p[i]
	}
	return p
}

// permute reorders objects by the permutation p.
func permute(objects []TrustObject, p []int) []TrustObject {
	out := make([]TrustObject, len(objects))
	for i, j := range p {
		out[i] = objects[j]
	}
	return out
}

// assertSameCommitment fails the test unless got matches want on root,
// leaf order, and marshaled bytes.
func assertSameCommitment(t *testing.T, got, want *Commitment, wantBytes []byte, what string) {
	t.Helper()
	if subtle.ConstantTimeCompare(got.Root[:], want.Root[:]) != 1 {
		t.Errorf("%s: Root = %x, want %x", what, got.Root, want.Root)
	}
	if got.Size != want.Size {
		t.Errorf("%s: Size = %d, want %d", what, got.Size, want.Size)
	}
	if len(got.LeafHashes) != len(want.LeafHashes) {
		t.Fatalf("%s: len(LeafHashes) = %d, want %d", what, len(got.LeafHashes), len(want.LeafHashes))
	}
	for i := range got.LeafHashes {
		if subtle.ConstantTimeCompare(got.LeafHashes[i][:], want.LeafHashes[i][:]) != 1 {
			t.Errorf("%s: LeafHashes[%d] = %x, want %x", what, i, got.LeafHashes[i], want.LeafHashes[i])
		}
	}
	gotBytes, err := Marshal(got)
	if err != nil {
		t.Fatalf("%s: Marshal() err = %v, want nil", what, err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Errorf("%s: Marshal() = %s, want %s", what, gotBytes, wantBytes)
	}
}

// TestDeterminism_ShuffledOrder builds the same object set under several
// deterministic permutations — identity, reversed, and seeded shuffles —
// and asserts byte-identical commitments. The whole comparison runs twice
// to prove repeatability across repeated runs in the same process.
func TestDeterminism_ShuffledOrder(t *testing.T) {
	t.Parallel()

	const n = 64
	base := vectorObjects(n)

	reversed := make([]int, n)
	for i := range reversed {
		reversed[i] = n - 1 - i
	}
	perms := []struct {
		name string
		p    []int
	}{
		{"identity", permutation(n, 0)},
		{"reversed", reversed},
		{"shuffle seed 1", permutation(n, 1)},
		{"shuffle seed 2", permutation(n, 2)},
		{"shuffle seed 0xdeadbeef", permutation(n, 0xdeadbeef)},
	}

	for run := 0; run < 2; run++ {
		var first *Commitment
		var firstBytes []byte
		for _, tc := range perms {
			c := mustBuild(t, permute(base, tc.p))
			b, err := Marshal(c)
			if err != nil {
				t.Fatalf("run %d %s: Marshal() err = %v, want nil", run, tc.name, err)
			}
			if first == nil {
				first, firstBytes = c, b
				continue
			}
			assertSameCommitment(t, c, first, firstBytes, fmt.Sprintf("run %d %s vs first", run, tc.name))
		}
	}
}

// TestDeterminism_ConcurrentBuildVerify runs Build + InclusionProof +
// VerifyInclusion from many goroutines on independent object sets and
// asserts every root equals the serially computed expectation. Run under
// -race to prove the shared hasher and tree construction are race-free.
func TestDeterminism_ConcurrentBuildVerify(t *testing.T) {
	t.Parallel()

	const (
		workers  = 16
		perSet   = 33
		verified = 5
	)

	// Expected roots are computed serially before any goroutine starts.
	expected := make([][32]byte, workers)
	sets := make([][]TrustObject, workers)
	for w := 0; w < workers; w++ {
		objs := make([]TrustObject, perSet)
		for i := range objs {
			objs[i] = testObject{seed: w*1000 + i}
		}
		sets[w] = objs
		expected[w] = mustBuild(t, objs).Root
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			c, err := Build(sets[w])
			if err != nil {
				t.Errorf("worker %d: Build() err = %v, want nil", w, err)
				return
			}
			if subtle.ConstantTimeCompare(c.Root[:], expected[w][:]) != 1 {
				t.Errorf("worker %d: Root = %x, want %x", w, c.Root, expected[w])
			}
			for i := 0; i < verified; i++ {
				obj := sets[w][i*perSet/verified]
				p, err := InclusionProof(c, obj)
				if err != nil {
					t.Errorf("worker %d object %d: InclusionProof() err = %v, want nil", w, i, err)
					continue
				}
				if err := VerifyInclusion(c.Root, p, obj); err != nil {
					t.Errorf("worker %d object %d: VerifyInclusion() err = %v, want nil", w, i, err)
				}
			}
		}(w)
	}
	wg.Wait()
}
