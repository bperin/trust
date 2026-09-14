package commitment

import (
	"fmt"
	"math/big"

	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/crypto/hash"
)

// deriveNamespacePrefix scopes the deterministic anchor derivation.
const deriveNamespacePrefix = "TrustCommitment/"

// Anchor binds a commitment contract address to an EVM chain ID.
type Anchor struct {
	// ChainID is the [EIP-155] chain ID the anchor lives on.
	ChainID *big.Int
	// Contract is the 20-byte address of the commitment contract.
	Contract ethereum.Address
}

// NewAnchor returns an Anchor for chainID and contract after validation.
func NewAnchor(chainID *big.Int, contract ethereum.Address) (*Anchor, error) {
	a := &Anchor{ChainID: chainID, Contract: contract}
	if err := a.Validate(); err != nil {
		return nil, fmt.Errorf("commitment: new anchor: %w", err)
	}
	return a, nil
}

// DeriveAnchor returns the deterministic anchor for a (chainID,
// namespace) pair: the contract is the last 20 bytes of the
// Keccak-256 digest of "TrustCommitment/" || namespace || uint256BE(chainID).
// This is a package convention, not an on-chain factory lookup.
func DeriveAnchor(chainID *big.Int, namespace string) (*Anchor, error) {
	if err := validateChainID(chainID); err != nil {
		return nil, err
	}
	id := uint256BE(chainID)

	buf := make([]byte, 0, len(deriveNamespacePrefix)+len(namespace)+len(id))
	buf = append(buf, deriveNamespacePrefix...)
	buf = append(buf, namespace...)
	buf = append(buf, id[:]...)
	digest := hash.NewKeccak256().Sum(buf)

	a := &Anchor{ChainID: chainID}
	copy(a.Contract[:], digest[12:])
	return a, nil
}

// ParseAnchor returns an Anchor for chainID and a hex contract
// address, validating the EIP-55 checksum via ethereum.ParseAddress.
func ParseAnchor(chainID *big.Int, s string) (*Anchor, error) {
	if err := validateChainID(chainID); err != nil {
		return nil, err
	}
	addr, err := ethereum.ParseAddress(s)
	if err != nil {
		return nil, fmt.Errorf("commitment: parse contract address: %w", err)
	}
	return &Anchor{ChainID: chainID, Contract: addr}, nil
}

// Validate checks that the anchor has a usable chain ID and a
// non-zero contract address.
func (a *Anchor) Validate() error {
	if a == nil {
		return ErrNilAnchor
	}
	if err := validateChainID(a.ChainID); err != nil {
		return err
	}
	if a.Contract == (ethereum.Address{}) {
		return fmt.Errorf("%w: zero contract address", ErrInvalidAnchor)
	}
	return nil
}

// validateChainID rejects a chain ID that is nil, non-positive, or
// does not fit in 256 bits.
func validateChainID(chainID *big.Int) error {
	if chainID == nil || chainID.Sign() <= 0 || chainID.BitLen() > 256 {
		return fmt.Errorf("%w: chain ID must be positive and fit in 256 bits", ErrInvalidAnchor)
	}
	return nil
}

// uint256BE encodes a validated chain ID as a 32-byte big-endian
// left-padded integer. Callers must validate chainID first.
func uint256BE(chainID *big.Int) [32]byte {
	var out [32]byte
	chainID.FillBytes(out[:])
	return out
}
