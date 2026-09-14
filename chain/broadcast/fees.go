package broadcast

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/bperin/trust/chain/rpc"
)

// ErrInvalidBlockTag is returned when a block tag is not a named tag
// or a valid hex block-number quantity. Checked with errors.Is.
var ErrInvalidBlockTag = errors.New("broadcast: invalid block tag")

// FetchNonce returns the next transaction nonce for address by calling
// eth_getTransactionCount at the given block tag. blockTag must be a
// named tag — "latest", "earliest", "pending", "safe", "finalized" —
// or a hex block number; use "pending" to account for transactions in
// flight. An invalid tag returns ErrInvalidBlockTag before any RPC is
// issued.
func FetchNonce(ctx context.Context, client rpc.Client, address string, blockTag string) (uint64, error) {
	if client == nil {
		return 0, fmt.Errorf("broadcast: nil rpc client")
	}
	if !validBlockTag(blockTag) {
		return 0, fmt.Errorf("broadcast: %w: %q", ErrInvalidBlockTag, blockTag)
	}
	hex, err := client.GetTransactionCount(ctx, address, blockTag)
	if err != nil {
		return 0, fmt.Errorf("broadcast: get transaction count: %w", err)
	}
	nonce, err := rpc.ParseBlockNumber(hex)
	if err != nil {
		return 0, fmt.Errorf("broadcast: parse nonce: %w", err)
	}
	return nonce, nil
}

// validBlockTag reports whether tag is a named block tag or a hex
// block-number quantity.
func validBlockTag(tag string) bool {
	switch tag {
	case "latest", "earliest", "pending", "safe", "finalized":
		return true
	}
	_, err := rpc.ParseQuantity(tag)
	return err == nil
}

// EstimateGasLimit estimates the gas required to execute call by
// calling eth_estimateGas. call is the transaction call object (from,
// to, value, data, etc.) as a map matching the provider's JSON shape.
func EstimateGasLimit(ctx context.Context, client rpc.Client, call map[string]interface{}) (uint64, error) {
	if client == nil {
		return 0, fmt.Errorf("broadcast: nil rpc client")
	}
	hex, err := client.EstimateGas(ctx, call)
	if err != nil {
		return 0, fmt.Errorf("broadcast: estimate gas: %w", err)
	}
	gas, err := rpc.ParseBlockNumber(hex)
	if err != nil {
		return 0, fmt.Errorf("broadcast: parse gas estimate: %w", err)
	}
	return gas, nil
}

// FetchFees returns the node's gas price and priority fee suggestions
// via eth_gasPrice and eth_maxPriorityFeePerGas. gasPrice is the
// provider's suggested total per-gas price (base fee plus tip on
// EIP-1559 chains), not the protocol base fee itself. If either RPC
// fails, the other is not attempted.
func FetchFees(ctx context.Context, client rpc.Client) (gasPrice, priorityFee *big.Int, err error) {
	if client == nil {
		return nil, nil, fmt.Errorf("broadcast: nil rpc client")
	}
	priorityHex, err := client.MaxPriorityFeePerGas(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("broadcast: max priority fee per gas: %w", err)
	}
	priorityFee, err = rpc.ParseQuantity(priorityHex)
	if err != nil {
		return nil, nil, fmt.Errorf("broadcast: parse priority fee: %w", err)
	}
	gasHex, err := client.GasPrice(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("broadcast: gas price: %w", err)
	}
	gasPrice, err = rpc.ParseQuantity(gasHex)
	if err != nil {
		return nil, nil, fmt.Errorf("broadcast: parse gas price: %w", err)
	}
	return gasPrice, priorityFee, nil
}
