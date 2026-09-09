package hash

import "crypto/sha256"

// SHA256 implements [FIPS 180-4] — the NIST SHA-256 hash function.
// SHA-256 is a Merkle-Damgård construction with a Davies-Meyer compression
// function over 64 rounds of 32-bit ARX operations. It produces a 256-bit
// (32-byte) digest with 128 bits of collision resistance.
//
// CNSA 2.0 approves SHA-256 for unclassified systems. For TOP SECRET
// systems, SHA-384 is required per [CNSA 2.0] (SHA-256 is not listed for
// TS). This wrapper provides SHA-256 only; SHA-384 would require a
// separate wrapper.
type SHA256 struct{}

// NewSHA256 returns a new [FIPS 180-4] SHA-256 hasher.
func NewSHA256() *SHA256 {
	return &SHA256{}
}

// Sum implements [FIPS 180-4] §6.2 — hashes data and returns a fixed-size
// 32-byte digest. The returned [32]byte avoids a heap allocation compared
// to a slice return. For cases where a slice is needed, use SumBytes.
//
// Nil input is treated as empty input and produces the same digest as
// a zero-length slice. This matches crypto/sha256 behavior.
func (s *SHA256) Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// SumBytes implements [FIPS 180-4] §6.2 — hashes data and returns a 32-byte
// slice. This is a convenience wrapper around Sum that returns a slice
// instead of a fixed-size array. Prefer Sum when the caller can use
// [32]byte directly to avoid an allocation.
func (s *SHA256) SumBytes(data []byte) []byte {
	h := s.Sum(data)
	return h[:]
}
