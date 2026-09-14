package secp256k1

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/bperin/trust/crypto/hash"
)

// EVMAddress derives the [Ethereum Yellow Paper] §7.4 address from a
// secp256k1 public key. The address is the last 20 bytes of the
// Keccak-256 hash of the uncompressed public key point (X || Y, 64
// bytes, no 0x04 prefix), with [EIP-55] mixed-case checksumming.
//
// Returns a 42-character string: "0x" + 40 hex chars with EIP-55
// checksum.
func EVMAddress(pub *PublicKey) (string, error) {
	if pub == nil || pub.key == nil {
		return "", fmt.Errorf("secp256k1: nil public key")
	}

	// Decompress the public key to get (X, Y) as 64 bytes.
	// dcrd SerializeUncompressed returns 65 bytes: 0x04 || X || Y.
	uncompressed := pub.key.SerializeUncompressed()
	if len(uncompressed) != 65 {
		return "", fmt.Errorf("secp256k1: invalid uncompressed key length %d", len(uncompressed))
	}

	// Keccak-256 of X || Y (skip the 0x04 prefix).
	k := hash.NewKeccak256()
	digest := k.SumBytes(uncompressed[1:])

	// Last 20 bytes = address.
	addr := digest[12:]

	// EIP-55 checksum.
	return checksumAddress(addr), nil
}

// checksumAddress applies [EIP-55] mixed-case checksumming to a
// 20-byte address. Returns "0x" + 40 hex chars with EIP-55 checksum.
func checksumAddress(addr []byte) string {
	// Lowercase hex without 0x.
	lower := hex.EncodeToString(addr)

	// Keccak-256 hash the lowercase hex string (ASCII bytes, no 0x).
	k := hash.NewKeccak256()
	hashHex := k.SumBytes([]byte(lower))

	// Build checksummed address: for each nibble, if it's a letter
	// and the corresponding hash nibble >= 8, uppercase it.
	result := make([]byte, 40)
	for i := 0; i < 40; i++ {
		c := lower[i]
		if c >= 'a' && c <= 'f' {
			// Get the corresponding hash nibble.
			hashNibble := hashHex[i/2]
			if i%2 == 0 {
				hashNibble >>= 4
			} else {
				hashNibble &= 0x0f
			}
			if hashNibble >= 8 {
				c -= 32 // uppercase
			}
		}
		result[i] = c
	}

	return "0x" + string(result)
}

// ChecksumAddress applies [EIP-55] checksumming to a hex address
// string. Accepts addresses with or without the "0x" prefix, in any
// case. Returns the checksummed address with "0x" prefix.
//
// This is useful for checksumming addresses from external sources.
// For addresses derived via EVMAddress, the checksum is already
// applied.
func ChecksumAddress(addr string) string {
	// Strip 0x prefix if present.
	addr = strings.TrimPrefix(addr, "0x")
	addr = strings.TrimPrefix(addr, "0X")

	// Decode hex to bytes.
	b, err := hex.DecodeString(addr)
	if err != nil || len(b) != 20 {
		// If not a valid 20-byte hex address, return as-is with 0x.
		return "0x" + addr
	}

	return checksumAddress(b)
}
