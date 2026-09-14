package commitment

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/bperin/trust/chain/rpc"
)

// Verify binds a Merkle root to a confirmed on-chain transaction
// (or validates the EIP-712 proof offline when prov is nil), mapping
// each failure to its distinct sentinel.
func Verify(ctx context.Context, a *Anchor, root [32]byte, p CommitmentProof, prov Provider) error {
	if a == nil {
		return ErrNilAnchor
	}

	if p.ChainID == nil || p.ChainID.Cmp(a.ChainID) != 0 {
		return fmt.Errorf("commitment: %w: proof chain ID does not match anchor", ErrChainIDMismatch)
	}
	if p.Contract != a.Contract {
		return fmt.Errorf("commitment: %w: proof contract does not match anchor", ErrChainIDMismatch)
	}

	if _, err := VerifyCommitmentProof(p); err != nil {
		return err
	}

	if prov == nil {
		if subtle.ConstantTimeCompare(p.Root[:], root[:]) != 1 {
			return fmt.Errorf("commitment: %w: proof root does not match expected root", ErrRootMismatch)
		}
		return nil
	}

	head, err := prov.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("commitment: block number: %w", err)
	}
	if head < p.BlockNumber {
		return fmt.Errorf("commitment: %w: head %d < proof block %d", ErrNotConfirmed, head, p.BlockNumber)
	}

	txHash := "0x" + hex.EncodeToString(p.TxHash[:])
	r, err := prov.Receipt(ctx, txHash)
	if err != nil {
		return fmt.Errorf("commitment: receipt: %w", err)
	}
	if r == nil || r.Status != 1 {
		return fmt.Errorf("commitment: %w: transaction not confirmed", ErrNotConfirmed)
	}

	blockTag := rpc.FormatQuantity(new(big.Int).SetUint64(p.BlockNumber))
	onChain, err := prov.Root(ctx, p.Contract, blockTag)
	if err != nil {
		return fmt.Errorf("commitment: root: %w", err)
	}
	if subtle.ConstantTimeCompare(onChain[:], root[:]) != 1 {
		return fmt.Errorf("commitment: %w: on-chain root does not match expected root", ErrRootMismatch)
	}
	return nil
}
