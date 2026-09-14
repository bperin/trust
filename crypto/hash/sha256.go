package hash

import "crypto/sha256"

// SHA256 implements [FIPS 180-4] — the NIST SHA-256 hash function.
// Produces a 256-bit (32-byte) digest with 128 bits of collision resistance.
type SHA256 struct{}

// NewSHA256 returns a new SHA-256 hasher.
func NewSHA256() *SHA256 {
	return &SHA256{}
}

// Sum hashes data and returns a 32-byte digest. Nil input is treated
// as empty.
func (s *SHA256) Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// SumBytes hashes data and returns a 32-byte slice. Convenience wrapper
// around Sum.
func (s *SHA256) SumBytes(data []byte) []byte {
	h := s.Sum(data)
	return h[:]
}
