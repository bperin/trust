package hash

import "golang.org/x/crypto/sha3"

// SHA3_256 implements [FIPS 202] — the NIST SHA-3-256 hash function.
// SHA-3 uses a sponge construction with the Keccak-f[1600] permutation,
// fundamentally different from SHA-2's Merkle-Damgård construction. It
// produces a 256-bit (32-byte) digest with 128 bits of collision resistance.
//
// SHA-3 is FIPS-approved but not in the CNSA 2.0 suite (which specifies
// SHA-384 for TOP SECRET). This wrapper provides SHA-3-256 only.
//
// Note: SHA-3-256 is NOT the same as Keccak-256. SHA-3 uses FIPS 202
// padding (0x06); Keccak-256 uses the original Keccak padding (0x01).
// Ethereum uses Keccak-256, not SHA-3. Use NewKeccak256 for EVM work.
type SHA3_256 struct{}

// NewSHA3_256 returns a new [FIPS 202] SHA-3-256 hasher.
func NewSHA3_256() *SHA3_256 {
	return &SHA3_256{}
}

// Sum implements [FIPS 202] §6.1 — hashes data and returns a fixed-size
// 32-byte digest. The returned [32]byte avoids a heap allocation compared
// to a slice return. For cases where a slice is needed, use SumBytes.
//
// Nil input is treated as empty input and produces the same digest as
// a zero-length slice.
func (s *SHA3_256) Sum(data []byte) [32]byte {
	h := sha3.New256()
	_, _ = h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// SumBytes implements [FIPS 202] §6.1 — hashes data and returns a 32-byte
// slice. This is a convenience wrapper around Sum that returns a slice
// instead of a fixed-size array. Prefer Sum when the caller can use
// [32]byte directly to avoid an allocation.
func (s *SHA3_256) SumBytes(data []byte) []byte {
	h := s.Sum(data)
	return h[:]
}
