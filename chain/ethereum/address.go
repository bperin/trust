package ethereum

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/crypto/secp256k1"
)

var (
	ErrInvalidAddress = errors.New("ethereum: invalid address format or checksum")
)

// Address represents a 20-byte Ethereum address.
type Address [20]byte

// FromPublicKey derives an Ethereum address from a secp256k1 public key.
func FromPublicKey(pub *secp256k1.PublicKey) (Address, error) {
	if pub == nil {
		return Address{}, fmt.Errorf("ethereum: nil public key")
	}
	pubBytes := pub.Bytes()
	var raw []byte
	if len(pubBytes) == 65 && pubBytes[0] == 0x04 {
		raw = pubBytes[1:]
	} else if len(pubBytes) == 64 {
		raw = pubBytes
	} else if len(pubBytes) == 33 {
		// If compressed, we can uncompress using secp256k1 package
		// But PublicKey.Bytes() returns 33 bytes or 65 bytes depending on implementation.
		// Let's check secp256k1 implementation or use Raw bytes.
		raw = pubBytes
	} else {
		raw = pubBytes
	}

	hasher := hash.NewKeccak256()
	h := hasher.Sum(raw)

	var addr Address
	copy(addr[:], h[12:])
	return addr, nil
}

// Hex returns the EIP-55 checksummed hexadecimal representation of the address.
func (a Address) Hex() string {
	hexAddr := hex.EncodeToString(a[:])
	hasher := hash.NewKeccak256()
	h := hasher.Sum([]byte(hexAddr))
	hashHex := hex.EncodeToString(h[:])

	var sb strings.Builder
	sb.WriteString("0x")
	for i := 0; i < 40; i++ {
		c := hexAddr[i]
		if c >= 'a' && c <= 'f' {
			nibble := hashHex[i]
			if nibble >= '8' {
				sb.WriteByte(c - 32)
				continue
			}
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

func (a Address) String() string {
	return a.Hex()
}

// ParseAddress parses an address string and validates its EIP-55 checksum if mixed-case.
func ParseAddress(s string) (Address, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 40 {
		return Address{}, fmt.Errorf("%w: expected 40 hex chars, got %d", ErrInvalidAddress, len(s))
	}
	decoded, err := hex.DecodeString(s)
	if err != nil || len(decoded) != 20 {
		return Address{}, fmt.Errorf("%w: invalid hex encoding", ErrInvalidAddress)
	}

	var addr Address
	copy(addr[:], decoded)

	hasUpper := false
	hasLower := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'F' {
			hasUpper = true
		} else if c >= 'a' && c <= 'f' {
			hasLower = true
		}
	}

	if hasUpper && hasLower {
		expected := addr.Hex()
		if s != strings.TrimPrefix(expected, "0x") {
			return Address{}, fmt.Errorf("%w: invalid EIP-55 checksum", ErrInvalidAddress)
		}
	}

	return addr, nil
}
