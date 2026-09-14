package wallet

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bperin/trust/chain/ethereum"
)

// Sentinel errors returned by ValidateTransaction. Check with errors.Is;
// wrap with fmt.Errorf and %w at boundaries.
//
// ErrInvalidType is shared with decode.go (defined there).
var (
	// ErrInvalidRLP indicates the raw transaction could not be RLP-decoded
	// or contained non-canonical encoding.
	ErrInvalidRLP = errors.New("wallet: invalid or non-canonical RLP")
	// ErrInvalidSignature indicates ecrecover could not recover a public
	// key from the signature and signing hash, or the recovered sender
	// is the zero address.
	ErrInvalidSignature = errors.New("wallet: invalid signature recovery")
	// ErrChainIDMismatch indicates the transaction's chain ID does not
	// match the expected chain ID.
	ErrChainIDMismatch = errors.New("wallet: chain ID mismatch")
	// ErrHighS indicates the s component of the signature exceeds n/2
	// per [EIP-2], making it non-canonical.
	ErrHighS = errors.New("wallet: high-s signature (EIP-2)")
	// ErrInvalidV indicates the v/y-parity field is not canonical for the
	// transaction type.
	ErrInvalidV = errors.New("wallet: invalid v/y-parity")
	// ErrFieldSanity indicates a decoded field has an invalid value
	// (negative, oversized, or wrong length).
	ErrFieldSanity = errors.New("wallet: field sanity check failed")
)

// secp256k1N is the curve order n for secp256k1 per [SEC 2 v2] §2.4:
//
//	n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
//
// It is used for [EIP-2] low-s validation: s must be <= n/2.
var secp256k1N = func() *big.Int {
	n, ok := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	if !ok {
		panic("wallet: invalid secp256k1 curve order constant")
	}
	return n
}()

// secp256k1HalfN is n/2, the [EIP-2] threshold above which s is high.
var secp256k1HalfN = func() *big.Int {
	return new(big.Int).Rsh(secp256k1N, 1)
}()

// ValidateTransaction validates a raw [EIP-2718] typed transaction against
// the expected chain ID. It decodes the transaction, checks field sanity,
// verifies ecrecover succeeds, confirms the chain ID matches, validates
// the v/y-parity canonicity, and enforces [EIP-2] low-s canonicalization.
//
// For legacy (type 0) transactions, the chain ID is derived from the v
// field per [EIP-155]: v == 27 or 28 indicates a pre-EIP-155 transaction
// with no chain ID (the expectedChainID is not checked). Otherwise the
// chain ID is (v - 35) / 2.
//
// For type-1 ([EIP-2930]) and type-2 ([EIP-1559]) transactions, the chain
// ID is the explicit chainId field in the RLP payload.
//
// [EIP-2]: https://eips.ethereum.org/EIPS/eip-2
// [EIP-155]: https://eips.ethereum.org/EIPS/eip-155
// [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
// [EIP-2930]: https://eips.ethereum.org/EIPS/eip-2930
// [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559
//
// [SEC 2 v2]: https://www.secg.org/sec2-v2.pdf
func ValidateTransaction(raw []byte, expectedChainID *big.Int) error {
	decoded, err := DecodeTransaction(raw)
	if err != nil {
		// Map decode errors to validation sentinels.
		if errors.Is(err, ErrInvalidType) {
			return fmt.Errorf("%w: %v", ErrInvalidType, err)
		}
		return fmt.Errorf("%w: %v", ErrInvalidRLP, err)
	}

	// Field sanity checks.
	if err := checkFieldSanity(decoded); err != nil {
		return err
	}

	// Signature recovery check: sender must be non-zero.
	if decoded.Sender == (ethereum.Address{}) {
		return fmt.Errorf("%w: recovered sender is zero address", ErrInvalidSignature)
	}

	// Chain ID match.
	if err := checkChainID(decoded, expectedChainID); err != nil {
		return err
	}

	// v/y-parity canonicity.
	if err := checkV(decoded); err != nil {
		return err
	}

	// EIP-2 low-s.
	s := new(big.Int).SetBytes(decoded.S)
	if s.Cmp(secp256k1HalfN) > 0 {
		return fmt.Errorf("%w: s exceeds n/2", ErrHighS)
	}

	return nil
}

// checkFieldSanity validates that decoded fields are within sane bounds.
func checkFieldSanity(d *DecodedTx) error {
	// Nonce and gas limit are uint64 — always non-negative by type.
	// Value must be non-negative.
	if d.Value != nil && d.Value.Sign() < 0 {
		return fmt.Errorf("%w: negative value", ErrFieldSanity)
	}
	// GasPrice must be non-negative (type 0 and 1).
	if d.GasPrice != nil && d.GasPrice.Sign() < 0 {
		return fmt.Errorf("%w: negative gas price", ErrFieldSanity)
	}
	// MaxPriorityFeePerGas must be non-negative (type 2).
	if d.MaxPriorityFeePerGas != nil && d.MaxPriorityFeePerGas.Sign() < 0 {
		return fmt.Errorf("%w: negative max priority fee", ErrFieldSanity)
	}
	// MaxFeePerGas must be non-negative (type 2).
	if d.MaxFeePerGas != nil && d.MaxFeePerGas.Sign() < 0 {
		return fmt.Errorf("%w: negative max fee", ErrFieldSanity)
	}
	// ChainID must be non-negative if present.
	if d.ChainID != nil && d.ChainID.Sign() < 0 {
		return fmt.Errorf("%w: negative chain ID", ErrFieldSanity)
	}
	// To must be 20 bytes or nil (contract creation). The decode path
	// already enforces this via asAddress, but double-check.
	if d.To != nil && len(d.To[:]) != 20 {
		return fmt.Errorf("%w: destination address not 20 bytes", ErrFieldSanity)
	}
	// R and S must be non-empty and <= 32 bytes.
	if len(d.R) == 0 || len(d.R) > 32 {
		return fmt.Errorf("%w: r length %d out of range", ErrFieldSanity, len(d.R))
	}
	if len(d.S) == 0 || len(d.S) > 32 {
		return fmt.Errorf("%w: s length %d out of range", ErrFieldSanity, len(d.S))
	}
	return nil
}

// checkChainID verifies the transaction's chain ID matches the expected
// chain ID. For pre-EIP-155 legacy transactions (v == 27 or 28), the
// chain ID is not checked.
func checkChainID(d *DecodedTx, expected *big.Int) error {
	if d.Type == 0 {
		// Legacy: v == 27 or 28 → pre-EIP-155, no chain ID check.
		v := new(big.Int).SetBytes(d.V)
		if v.Cmp(big.NewInt(27)) == 0 || v.Cmp(big.NewInt(28)) == 0 {
			return nil
		}
		// EIP-155: chainID = (v - 35) / 2.
		if d.ChainID == nil {
			return fmt.Errorf("%w: legacy EIP-155 tx has nil chain ID", ErrFieldSanity)
		}
	} else {
		// Type 1 and 2: explicit chainId field.
		if d.ChainID == nil {
			return fmt.Errorf("%w: typed tx has nil chain ID", ErrFieldSanity)
		}
	}

	if expected == nil {
		return nil
	}
	if d.ChainID.Cmp(expected) != 0 {
		return fmt.Errorf("%w: got %s, want %s", ErrChainIDMismatch, d.ChainID.String(), expected.String())
	}
	return nil
}

// checkV validates the v/y-parity field is canonical for the transaction
// type.
func checkV(d *DecodedTx) error {
	v := new(big.Int).SetBytes(d.V)

	switch d.Type {
	case 0:
		// Legacy: v == 27, 28 (pre-EIP-155), or v = 35 + 2*chainID + recID.
		if v.Cmp(big.NewInt(27)) == 0 || v.Cmp(big.NewInt(28)) == 0 {
			return nil
		}
		// EIP-155: v must be >= 35. Values in [29, 34] are invalid
		// (not pre-EIP-155, not EIP-155). The guard below catches
		// all v < 35, including [29, 34].
		if v.Cmp(big.NewInt(35)) < 0 {
			return fmt.Errorf("%w: legacy v %s < 35", ErrInvalidV, v.String())
		}
		// v = 35 + 2*chainID + recID. (v - 35) / 2 is the chain ID
		// and (v - 35) % 2 is recID (0 or 1). Both are always valid
		// for v >= 35.
	case 1, 2:
		// Typed: v = y-parity (0 or 1).
		if v.Cmp(big.NewInt(0)) != 0 && v.Cmp(big.NewInt(1)) != 0 {
			return fmt.Errorf("%w: typed tx v %s not 0 or 1", ErrInvalidV, v.String())
		}
	default:
		return fmt.Errorf("%w: type %d", ErrInvalidType, d.Type)
	}
	return nil
}
