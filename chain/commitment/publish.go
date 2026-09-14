package commitment

import (
	"context"
	"fmt"
	"math/big"

	"github.com/bperin/trust/chain/abi"
	"github.com/bperin/trust/chain/wallet"
)

// PublishSignature is the canonical Solidity signature of the
// commitment contract's root-publishing function.
const PublishSignature = "publishRoot(bytes32)"

// publishCallData ABI-encodes a publishRoot(bytes32) call for the
// given root: the 4-byte selector followed by the 32-byte root.
func publishCallData(root [32]byte) ([]byte, error) {
	body, err := abi.EncodeArgs([]abi.ABIType{abi.ABITypeBytes32}, []interface{}{root})
	if err != nil {
		return nil, fmt.Errorf("commitment: encode publish args: %w", err)
	}
	sel := abi.FunctionSelector(PublishSignature)
	return append(sel[:], body...), nil
}

// PublishConfig holds the resolved transaction parameters for a
// root-publishing transaction.
type PublishConfig struct {
	Nonce    uint64
	GasLimit uint64
	GasPrice *big.Int
}

// PublishOption configures a PublishConfig.
type PublishOption func(*PublishConfig)

// WithNonce sets the transaction nonce.
func WithNonce(n uint64) PublishOption {
	return func(c *PublishConfig) { c.Nonce = n }
}

// WithGasLimit sets the gas limit. A zero value is ignored.
func WithGasLimit(n uint64) PublishOption {
	return func(c *PublishConfig) {
		if n > 0 {
			c.GasLimit = n
		}
	}
}

// WithGasPrice sets the gas price. A nil value is ignored.
func WithGasPrice(p *big.Int) PublishOption {
	return func(c *PublishConfig) {
		if p != nil {
			c.GasPrice = p
		}
	}
}

// Publish ABI-encodes a publishRoot(bytes32) call, signs an EIP-155
// legacy transaction with the wallet, submits it via the provider, and
// returns the confirmed receipt.
func Publish(ctx context.Context, a *Anchor, root [32]byte, w *wallet.Wallet, p Provider, opts ...PublishOption) (Receipt, error) {
	if a == nil {
		return Receipt{}, ErrNilAnchor
	}
	if w == nil {
		return Receipt{}, ErrNilWallet
	}
	if p == nil {
		return Receipt{}, fmt.Errorf("commitment: nil provider")
	}

	cfg := PublishConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.GasLimit == 0 {
		return Receipt{}, fmt.Errorf("commitment: %w: gas limit required", ErrMissingTxParams)
	}
	if cfg.GasPrice == nil {
		return Receipt{}, fmt.Errorf("commitment: %w: gas price required", ErrMissingTxParams)
	}

	data, err := publishCallData(root)
	if err != nil {
		return Receipt{}, err
	}

	contract := a.Contract
	tx := &wallet.LegacyTx{
		ChainID:  a.ChainID,
		Nonce:    cfg.Nonce,
		GasPrice: cfg.GasPrice,
		GasLimit: cfg.GasLimit,
		To:       &contract,
		Value:    big.NewInt(0),
		Data:     data,
	}

	raw, err := w.SignTx(tx)
	if err != nil {
		return Receipt{}, fmt.Errorf("commitment: sign tx: %w", err)
	}

	txHash, err := p.SendTx(ctx, raw)
	if err != nil {
		return Receipt{}, fmt.Errorf("commitment: send tx: %w", err)
	}

	r, err := p.Receipt(ctx, txHash)
	if err != nil {
		return Receipt{}, fmt.Errorf("commitment: receipt: %w", err)
	}
	if r == nil || r.Status != 1 {
		return Receipt{}, fmt.Errorf("commitment: %w: status %d", ErrNotConfirmed, statusOr(r))
	}
	return *r, nil
}

// statusOr returns the receipt status or 0 for a nil receipt.
func statusOr(r *Receipt) uint64 {
	if r == nil {
		return 0
	}
	return r.Status
}
