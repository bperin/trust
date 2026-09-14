package hash

import "github.com/zeebo/blake3"

// BLAKE3 implements the BLAKE3 hash function. Produces a 256-bit
// (32-byte) digest. BLAKE3 is not a NIST/FIPS standard — use SHA-256
// or SHA-384 for FIPS-required contexts.
type BLAKE3 struct{}

// NewBLAKE3 returns a new BLAKE3 hasher.
func NewBLAKE3() *BLAKE3 {
	return &BLAKE3{}
}

// Sum hashes data and returns a 32-byte digest. Nil input is treated as
// empty.
func (b *BLAKE3) Sum(data []byte) [32]byte {
	return blake3.Sum256(data)
}

// SumBytes hashes data and returns a 32-byte slice. Convenience wrapper
// around Sum.
func (b *BLAKE3) SumBytes(data []byte) []byte {
	h := b.Sum(data)
	return h[:]
}
