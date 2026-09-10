package merkle

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/bperin/trust/crypto/hash"
)

// Sentinel errors returned by New, Proof, and ConsistencyProof. Check them
// with errors.Is.
var (
	// ErrEmptyTree is returned by New when the tree has no leaves. The
	// [RFC 6962] §2.1 hash of an empty list is SHA-256 of the empty string;
	// this package treats an empty tree as a caller error instead.
	ErrEmptyTree = errors.New("merkle: tree requires at least one leaf")
	// ErrIndexOutOfRange is returned by Proof when the leaf index is negative
	// or not smaller than the leaf count.
	ErrIndexOutOfRange = errors.New("merkle: leaf index out of range")
	// ErrInvalidRange is returned by ConsistencyProof when the requested
	// (m, n) range violates the [RFC 6962] §2.1.2 constraint 0 < m < n or n
	// does not match the tree size.
	ErrInvalidRange = errors.New("merkle: invalid consistency proof range")
	// ErrTreeCorrupt is returned when an internal node lookup fails. It is
	// unreachable unless the tree was built with an inconsistent state.
	ErrTreeCorrupt = errors.New("merkle: internal node lookup failed")
)

// hasher is safe for concurrent use: SHA256 carries no state between Sum
// calls, matching the stateless [FIPS 180-4] definition.
var hasher = hash.NewSHA256()

// leafPrefix and nodePrefix are the [RFC 6962] §2.1 domain separators. They
// make leaf hashes and interior hashes distinguishable, which is required
// for second preimage resistance.
const (
	leafPrefix byte = 0x00
	nodePrefix byte = 0x01
)

// leafHash implements [RFC 6962] §2.1 — the hash of a single-entry list:
// SHA-256(0x00 || data).
func leafHash(data []byte) [32]byte {
	buf := make([]byte, 0, len(data)+1)
	buf = append(buf, leafPrefix)
	buf = append(buf, data...)
	return hasher.Sum(buf)
}

// nodeHash implements [RFC 6962] §2.1 — the hash of an interior node:
// SHA-256(0x01 || left || right). It allocates nothing: the input is
// assembled in a fixed 65-byte stack buffer.
func nodeHash(left, right [32]byte) [32]byte {
	var buf [65]byte
	buf[0] = nodePrefix
	copy(buf[1:], left[:])
	copy(buf[33:], right[:])
	return hasher.Sum(buf[:])
}

// largestPow2LessThan returns k, the largest power of two with k < n, as
// used by every [RFC 6962] §2.1 recursion. For n > 1 this satisfies
// k < n <= 2k.
func largestPow2LessThan(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// Tree is an immutable [RFC 6962] §2.1 Merkle hash tree. Levels[0] holds the
// leaf hashes; each next level pairs consecutive nodes and promotes the final
// odd node unchanged. This layout reproduces the RFC's recursive
// split-at-largest-power-of-two shape exactly, so every subtree hash the RFC
// algorithms reference is available as a single level entry.
type Tree struct {
	levels [][][32]byte
	size   int
}

// New implements [RFC 6962] §2.1 — it builds the Merkle hash tree over
// leaves. Leaf data is hashed once and never retained, so later mutation of
// the caller's slices cannot alter the tree. An empty leaf list is rejected.
func New(leaves [][]byte) (*Tree, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("merkle: build tree: %w", ErrEmptyTree)
	}
	t := &Tree{size: len(leaves)}
	level := make([][32]byte, len(leaves))
	for i, leaf := range leaves {
		level[i] = leafHash(leaf)
	}
	t.levels = append(t.levels, level)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, nodeHash(level[i], level[i+1]))
			} else {
				next = append(next, level[i])
			}
		}
		t.levels = append(t.levels, next)
		level = next
	}
	return t, nil
}

// Root implements [RFC 6962] §2.1 — it returns a copy of the Merkle Tree
// Hash of the tree. The copy is defensive: callers cannot mutate tree state
// through the returned slice.
func (t *Tree) Root() []byte {
	top := t.levels[len(t.levels)-1][0]
	root := make([]byte, 32)
	copy(root, top[:])
	return root
}

// Size returns the number of leaves in the tree.
func (t *Tree) Size() int {
	return t.size
}

// Proof implements [RFC 6962] §2.1.1 — the audit path for the leaf at index,
// ordered from the leaf level to the root. Steps carry the sibling hash and
// the sibling's side; the path for a single-leaf tree is empty.
func (t *Tree) Proof(index int) (AuditPath, error) {
	if index < 0 || index >= t.size {
		return AuditPath{}, fmt.Errorf("merkle: proof for index %d in tree of %d leaves: %w", index, t.size, ErrIndexOutOfRange)
	}
	var path AuditPath
	idx := index
	for level := 0; level+1 < len(t.levels); level++ {
		count := len(t.levels[level])
		if idx%2 == 1 || idx+1 < count {
			path.Steps = append(path.Steps, ProofStep{
				Hash:    t.levels[level][idx^1],
				IsRight: idx%2 == 0,
			})
		}
		idx /= 2
	}
	return path, nil
}

// AuditPath implements [RFC 6962] §2.1.1 — an ordered list of sibling hashes
// from the leaf level to the root. For consistency proofs the same type
// carries the [RFC 6962] §2.1.2 proof nodes, with IsRight recording whether
// each node commits to a right subtree.
type AuditPath struct {
	// Steps are the sibling hashes ordered from the leaf level toward the root.
	Steps []ProofStep
}

// ProofStep is one sibling hash in an audit path.
type ProofStep struct {
	// Hash is the sibling hash at this level.
	Hash [32]byte
	// IsRight reports whether the sibling sits on the right of the node being
	// recomputed. For consistency proof nodes it reports whether the node
	// commits to a right subtree.
	IsRight bool
}

// subtree returns the hash of the node covering exactly the leaf range
// [lo, hi). It descends from the root, following the pairing used to build
// the levels, and fails when the range does not align with a single node.
func (t *Tree) subtree(lo, hi int) ([32]byte, bool) {
	if lo < 0 || hi > t.size || lo >= hi {
		return [32]byte{}, false
	}
	j := len(t.levels) - 1
	p := 0
	for {
		coverLo := p << j
		coverHi := coverLo + 1<<j
		if coverHi > t.size {
			coverHi = t.size
		}
		if coverLo == lo && coverHi == hi {
			return t.levels[j][p], true
		}
		if j == 0 {
			return [32]byte{}, false
		}
		left, right := 2*p, 2*p+1
		if right >= len(t.levels[j-1]) {
			p = left
			j--
			continue
		}
		leftHi := coverLo + 1<<(j-1)
		switch {
		case hi <= leftHi:
			p = left
		case lo < leftHi:
			return [32]byte{}, false
		default:
			p = right
		}
		j--
	}
}

// ConsistencyProof implements [RFC 6962] §2.1.2 — the consistency proof that
// the first m leaves of the n-leaf tree are unchanged from the previous m
// leaf tree. It requires 0 < m < n and n to equal the tree size. The proof
// nodes are ordered deepest first, matching the SUBPROOF recursion.
func (t *Tree) ConsistencyProof(m, n int) (AuditPath, error) {
	if m <= 0 || m >= n {
		return AuditPath{}, fmt.Errorf("merkle: consistency proof for (%d, %d): %w", m, n, ErrInvalidRange)
	}
	if n != t.size {
		return AuditPath{}, fmt.Errorf("merkle: consistency proof for (%d, %d) in tree of %d leaves: %w", m, n, t.size, ErrInvalidRange)
	}
	var path AuditPath
	if !t.consistencySubproof(m, 0, n, true, &path) {
		return AuditPath{}, fmt.Errorf("merkle: consistency proof for (%d, %d): %w", m, n, ErrTreeCorrupt)
	}
	return path, nil
}

// consistencySubproof mirrors the [RFC 6962] §2.1.2 SUBPROOF recursion over
// the leaf range [lo, hi) with m old leaves, appending proof nodes in
// emission order.
func (t *Tree) consistencySubproof(m, lo, hi int, b bool, path *AuditPath) bool {
	if m == hi-lo {
		if !b {
			h, ok := t.subtree(lo, hi)
			if !ok {
				return false
			}
			path.Steps = append(path.Steps, ProofStep{Hash: h, IsRight: false})
		}
		return true
	}
	k := largestPow2LessThan(hi - lo)
	if m <= k {
		if !t.consistencySubproof(m, lo, lo+k, b, path) {
			return false
		}
		h, ok := t.subtree(lo+k, hi)
		if !ok {
			return false
		}
		path.Steps = append(path.Steps, ProofStep{Hash: h, IsRight: true})
		return true
	}
	if !t.consistencySubproof(m-k, lo+k, hi, false, path) {
		return false
	}
	h, ok := t.subtree(lo, lo+k)
	if !ok {
		return false
	}
	path.Steps = append(path.Steps, ProofStep{Hash: h, IsRight: false})
	return true
}

// Verify implements [RFC 6962] §2.1.1 — it recomputes the root from leaf and
// path and compares the result against root in constant time. It reports
// false for any malformed input, including a root that is not 32 bytes.
func Verify(root []byte, leaf []byte, path AuditPath) bool {
	if len(root) != 32 {
		return false
	}
	h := leafHash(leaf)
	for _, step := range path.Steps {
		if step.IsRight {
			h = nodeHash(h, step.Hash)
		} else {
			h = nodeHash(step.Hash, h)
		}
	}
	return subtle.ConstantTimeCompare(h[:], root) == 1
}

// proofCursor consumes consistency proof nodes in emission order.
type proofCursor struct {
	steps []ProofStep
	next  int
}

func (c *proofCursor) take() ([32]byte, bool) {
	if c.next >= len(c.steps) {
		return [32]byte{}, false
	}
	h := c.steps[c.next].Hash
	c.next++
	return h, true
}

// VerifyConsistency implements [RFC 6962] §2.1.2 — it recomputes both the
// m-leaf root and the n-leaf root from the proof and compares each against
// oldRoot and newRoot in constant time. A proof for m == n must be empty with
// identical roots. It reports false for any malformed input, including
// roots that are not 32 bytes, unconsumed trailing nodes, or 0 < m < n
// violations.
func VerifyConsistency(oldRoot, newRoot []byte, m, n int, path AuditPath) bool {
	if len(oldRoot) != 32 || len(newRoot) != 32 {
		return false
	}
	if m == n {
		return len(path.Steps) == 0 && subtle.ConstantTimeCompare(oldRoot, newRoot) == 1
	}
	if m <= 0 || m > n {
		return false
	}
	var old [32]byte
	copy(old[:], oldRoot)
	cur := &proofCursor{steps: path.Steps}
	newHash, oldHash, ok := verifySubproof(m, n, true, &old, cur)
	if !ok || cur.next != len(cur.steps) {
		return false
	}
	return subtle.ConstantTimeCompare(oldHash[:], oldRoot) == 1 &&
		subtle.ConstantTimeCompare(newHash[:], newRoot) == 1
}

// verifySubproof mirrors the [RFC 6962] §2.1.2 SUBPROOF recursion, consuming
// proof nodes in emission order and returning the recomputed n-leaf hash and
// m-leaf hash for the range. When b is true, old holds the caller's expected
// m-leaf hash for the range; when the recursion closes a right subtree,
// b becomes false and the range hash is taken from the proof instead.
func verifySubproof(m, n int, b bool, old *[32]byte, cur *proofCursor) (newHash, oldHash [32]byte, ok bool) {
	if m == n {
		if b {
			return *old, *old, true
		}
		h, got := cur.take()
		if !got {
			return [32]byte{}, [32]byte{}, false
		}
		return h, h, true
	}
	k := largestPow2LessThan(n)
	if m <= k {
		leftNew, leftOld, got := verifySubproof(m, k, b, old, cur)
		if !got {
			return [32]byte{}, [32]byte{}, false
		}
		rightRoot, got := cur.take()
		if !got {
			return [32]byte{}, [32]byte{}, false
		}
		return nodeHash(leftNew, rightRoot), leftOld, true
	}
	rightNew, rightOld, got := verifySubproof(m-k, n-k, false, nil, cur)
	if !got {
		return [32]byte{}, [32]byte{}, false
	}
	leftRoot, got := cur.take()
	if !got {
		return [32]byte{}, [32]byte{}, false
	}
	return nodeHash(leftRoot, rightNew), nodeHash(leftRoot, rightOld), true
}
