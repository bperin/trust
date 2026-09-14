package hash

import "golang.org/x/crypto/sha3"

// SHA3_256 implements [FIPS 202] — the NIST SHA-3-256 hash function.
// Produces a 256-bit (32-byte) digest with 128 bits of collision resistance.
//
// SHA-3-256 is NOT the same as Keccak-256. SHA-3 uses FIPS 202 padding
// (0x06); Keccak-256 uses the original Keccak padding (0x01). Ethereum
// uses Keccak-256, not SHA-3. Use NewKeccak256 for EVM work.
type SHA3_256 struct{}

// NewSHA3_256 returns a new SHA-3-256 hasher.
func NewSHA3_256() *SHA3_256 {
	return &SHA3_256{}
}

// Sum hashes data and returns a 32-byte digest. Nil input is treated as
// empty.
func (s *SHA3_256) Sum(data []byte) [32]byte {
	h := sha3.New256()
	_, _ = h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// SumBytes hashes data and returns a 32-byte slice. Convenience wrapper
// around Sum.
func (s *SHA3_256) SumBytes(data []byte) []byte {
	h := s.Sum(data)
	return h[:]
}
