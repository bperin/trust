// Package eip712 implements [EIP-712] typed structured data hashing.
// EIP-712 defines a domain separator, per-struct hashing, and a final
// signing digest that combines them:
//
//   - domainSeparator = keccak256(typeHash || abiEncoded(domainFields))
//   - structHash      = keccak256(typeHash || abiEncoded(structFields))
//   - digest          = keccak256(0x1901 || domainSeparator || structHash)
//
// The package owns hashing only; signing is delegated to
// [wallet.Wallet.SignDigest].
package eip712

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/wallet"
	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/crypto/secp256k1"
)

// ErrInvalidDomain is returned when a domain field cannot be encoded
// under the fixed five-field domain profile.
var ErrInvalidDomain = errors.New("eip712: invalid domain separator")

// keccak256 returns the 32-byte Keccak-256 digest of data.
func keccak256(data []byte) [32]byte {
	return hash.NewKeccak256().Sum(data)
}

// keccak256Concat returns the Keccak-256 digest of the concatenation of
// the given byte slices.
func keccak256Concat(parts ...[]byte) [32]byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	buf := make([]byte, 0, total)
	for _, p := range parts {
		buf = append(buf, p...)
	}
	return hash.NewKeccak256().Sum(buf)
}

// DomainSeparator is the [EIP-712] domain separator. It binds a signed
// message to a specific application, version, chain, and contract,
// preventing cross-domain replay.
//
// This package supports the canonical five-field profile:
//
//	EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)
//
// Every field participates in the hash, so ChainID must be a concrete
// uint256 (nil is rejected).
type DomainSeparator struct {
	Name              string
	Version           string
	ChainID           *big.Int
	VerifyingContract ethereum.Address
	Salt              [32]byte
}

// Validate checks that the domain fields are encodable under the fixed
// profile. ChainID must be non-nil, non-negative, and at most 2^256-1.
func (d DomainSeparator) Validate() error {
	if d.ChainID == nil {
		return fmt.Errorf("%w: chainId is nil (the fixed five-field profile requires a concrete uint256)", ErrInvalidDomain)
	}
	if d.ChainID.Sign() < 0 {
		return fmt.Errorf("%w: chainId %s is negative", ErrInvalidDomain, d.ChainID)
	}
	if d.ChainID.BitLen() > 256 {
		return fmt.Errorf("%w: chainId exceeds uint256 (%d bits)", ErrInvalidDomain, d.ChainID.BitLen())
	}
	return nil
}

// domainTypeHash is the Keccak-256 of the canonical EIP-712 domain
// type string.
var domainTypeHash = keccak256([]byte(
	"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
))

// Hash returns the [EIP-712] domain separator hash:
// keccak256(domainTypeHash || abiEncode(name, version, chainId,
// verifyingContract, salt)). Invalid domains return ErrInvalidDomain.
func (d DomainSeparator) Hash() ([32]byte, error) {
	if err := d.Validate(); err != nil {
		return [32]byte{}, err
	}

	// ABI-encode the fields in canonical order.
	nameHash := keccak256([]byte(d.Name))
	versionHash := keccak256([]byte(d.Version))

	chainID := encodeUint256(d.ChainID)
	contract := encodeAddress(d.VerifyingContract)
	salt := d.Salt[:]

	encoded := make([]byte, 0, 32*5)
	encoded = append(encoded, nameHash[:]...)
	encoded = append(encoded, versionHash[:]...)
	encoded = append(encoded, chainID...)
	encoded = append(encoded, contract...)
	encoded = append(encoded, salt...)

	return keccak256Concat(domainTypeHash[:], encoded), nil
}

// HashStruct returns the [EIP-712] struct hash:
// keccak256(typeHash || encodedFields). The caller provides the type
// hash and the ABI-encoded field values.
func HashStruct(typeHash []byte, encodedFields []byte) [32]byte {
	return keccak256Concat(typeHash, encodedFields)
}

// Digest returns the [EIP-712] signing digest:
// keccak256(0x1901 || domainSeparator || structHash).
func Digest(domainSeparator [32]byte, structHash [32]byte) [32]byte {
	prefix := []byte{0x19, 0x01}
	return keccak256Concat(prefix, domainSeparator[:], structHash[:])
}

// Sign computes the [EIP-712] digest from the domain separator and
// struct hash and signs it with the wallet, returning a 65-byte
// signature (r || s || v).
func Sign(w *wallet.Wallet, domainSeparator [32]byte, structHash [32]byte) ([]byte, error) {
	if w == nil {
		return nil, fmt.Errorf("eip712: nil wallet")
	}
	digest := Digest(domainSeparator, structHash)
	return w.SignDigest(digest[:])
}

// Recover recovers the signer's Ethereum address from a 65-byte
// EIP-712 signature, given the domain separator and struct hash. The
// recovery id is v - 27.
func Recover(sig []byte, domainSeparator [32]byte, structHash [32]byte) (ethereum.Address, error) {
	if len(sig) != 65 {
		return ethereum.Address{}, fmt.Errorf("eip712: signature must be 65 bytes, got %d", len(sig))
	}

	digest := Digest(domainSeparator, structHash)
	recID := sig[64] - 27
	if recID > 3 {
		return ethereum.Address{}, fmt.Errorf("eip712: invalid recovery id %d (v=%d)", recID, sig[64])
	}

	pub, err := secp256k1.RecoverPubKey(sig[:64], digest[:], recID)
	if err != nil {
		return ethereum.Address{}, fmt.Errorf("eip712: recover public key: %w", err)
	}

	addr, err := ethereum.FromPublicKey(pub)
	if err != nil {
		return ethereum.Address{}, fmt.Errorf("eip712: derive address: %w", err)
	}
	return addr, nil
}

// encodeUint256 ABI-encodes a uint256 as 32-byte big-endian. A nil or
// out-of-range value encodes as 32 zero bytes.
func encodeUint256(n *big.Int) []byte {
	out := make([]byte, 32)
	if n == nil || n.Sign() <= 0 || n.BitLen() > 256 {
		return out
	}
	b := n.Bytes()
	copy(out[32-len(b):], b)
	return out
}

// encodeAddress ABI-encodes an Ethereum address as a 32-byte
// left-padded value (12 zero bytes + 20 address bytes).
func encodeAddress(addr ethereum.Address) []byte {
	out := make([]byte, 32)
	copy(out[12:], addr[:])
	return out
}
