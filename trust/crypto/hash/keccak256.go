package hash

import "golang.org/x/crypto/sha3"

// Keccak256 implements [EIP-191] (original Keccak padding) — the hash function
// used by Ethereum. This is NOT SHA-3-256. SHA-3 uses FIPS 202 padding (0x06);
// Keccak-256 uses the original Keccak padding (0x01). They produce different
// digests for the same input.
//
// Ethereum adopted the original Keccak padding before NIST finalized FIPS 202
// with different padding. This is a historical accident — Ethereum launched in
// 2015, FIPS 202 was finalized in 2012.
//
// Use NewKeccak256 for EVM address derivation, EIP-712 typed data hashing,
// and EIP-191 signed message verification. Use NewSHA3_256 for FIPS 202
// SHA-3-256.
type Keccak256 struct{}

// NewKeccak256 returns a new [EIP-191] Keccak-256 hasher (original Keccak
// padding, not FIPS 202 SHA-3).
func NewKeccak256() *Keccak256 {
	return &Keccak256{}
}

// Sum implements [EIP-191] — hashes data using original Keccak padding and
// returns a fixed-size 32-byte digest. The returned [32]byte avoids a heap
// allocation compared to a slice return.
//
// Nil input is treated as empty input and produces the same digest as
// a zero-length slice.
//
// The per-call hasher is stack-allocated: sha3.NewLegacyKeccak256 is inlined
// here and escape analysis keeps &sha3.state on the stack (the interface
// calls are devirtualized to direct *sha3.state calls). This yields 0
// allocations per Sum — do not replace this with a sync.Pool, which would
// add indirection and GC-pinning overhead for no benefit. See
// BenchmarkKeccak256_Sum for the allocation profile.
func (k *Keccak256) Sum(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// SumBytes implements [EIP-191] — hashes data and returns a 32-byte slice.
// Convenience wrapper around Sum. Prefer Sum when the caller can use
// [32]byte directly to avoid an allocation.
func (k *Keccak256) SumBytes(data []byte) []byte {
	h := k.Sum(data)
	return h[:]
}
