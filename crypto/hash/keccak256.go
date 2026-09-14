package hash

import "golang.org/x/crypto/sha3"

// Keccak256 implements Keccak-256 — the hash function used by Ethereum.
// This is NOT SHA-3-256. SHA-3 uses FIPS 202 padding (0x06); Keccak-256
// uses the original Keccak padding (0x01). They produce different digests
// for the same input.
//
// Use NewKeccak256 for EVM address derivation, EIP-712 typed data hashing,
// and EIP-191 signed message verification. Use NewSHA3_256 for FIPS 202
// SHA-3-256.
type Keccak256 struct{}

// NewKeccak256 returns a new Keccak-256 hasher (original Keccak padding,
// not FIPS 202 SHA-3).
func NewKeccak256() *Keccak256 {
	return &Keccak256{}
}

// Sum hashes data and returns a 32-byte digest. Nil input is treated as
// empty.
func (k *Keccak256) Sum(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// SumBytes hashes data and returns a 32-byte slice. Convenience wrapper
// around Sum.
func (k *Keccak256) SumBytes(data []byte) []byte {
	h := k.Sum(data)
	return h[:]
}
