package hash

import "github.com/zeebo/blake3"

// BLAKE3 implements [BLAKE3 Spec, 2020] — the BLAKE3 hash function.
// BLAKE3 uses a Merkle tree of compression functions derived from the
// BLAKE2s round function. It is significantly faster than SHA-256 on
// modern CPUs with SIMD support and has built-in parallelism.
//
// BLAKE3 is NOT a NIST/FIPS standard. It is widely adopted in Zcash,
// IPFS, and content-addressed storage. For NSS or FIPS-required contexts,
// use SHA-256 or SHA-384 instead.
//
// Reference: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
type BLAKE3 struct{}

// NewBLAKE3 returns a new [BLAKE3 Spec, 2020] BLAKE3 hasher.
func NewBLAKE3() *BLAKE3 {
	return &BLAKE3{}
}

// Sum implements [BLAKE3 Spec, 2020] — hashes data and returns a fixed-size
// 32-byte digest. The returned [32]byte avoids a heap allocation compared
// to a slice return.
//
// Nil input is treated as empty input and produces the same digest as
// a zero-length slice.
func (b *BLAKE3) Sum(data []byte) [32]byte {
	return blake3.Sum256(data)
}

// SumBytes implements [BLAKE3 Spec, 2020] — hashes data and returns a
// 32-byte slice. Convenience wrapper around Sum. Prefer Sum when the
// caller can use [32]byte directly to avoid an allocation.
func (b *BLAKE3) SumBytes(data []byte) []byte {
	h := b.Sum(data)
	return h[:]
}
