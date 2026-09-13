package broadcast

import (
	"context"
	"fmt"
	"math/big"

	"github.com/bperin/chain/rpc"
)

// FetchNonce returns the next transaction nonce for address by calling
// eth_getTransactionCount at the "latest" block tag.
//
// The RPC method returns the nonce as a hex quantity string per
// [EIP-1474]; it is parsed via rpc.ParseBlockNumber, which rejects
// malformed input (empty string, missing 0x prefix, leading zeros,
// non-hex digits) and guards against uint64 overflow. The result is
// the number of transactions sent from address, which is the next
// nonce to use for a new transaction.
//
// RPC errors from the client are wrapped with fmt.Errorf and %w so
// callers can recover the underlying *rpc.RPCError via errors.As.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func FetchNonce(ctx context.Context, client rpc.Client, address string) (uint64, error) {
	if client == nil {
		return 0, fmt.Errorf("broadcast: nil rpc client")
	}
	hex, err := client.GetTransactionCount(ctx, address, "latest")
	if err != nil {
		return 0, fmt.Errorf("broadcast: get transaction count: %w", err)
	}
	nonce, err := rpc.ParseBlockNumber(hex)
	if err != nil {
		return 0, fmt.Errorf("broadcast: parse nonce: %w", err)
	}
	return nonce, nil
}

// EstimateGasLimit returns an estimate of the gas required to execute
// call by calling eth_estimateGas.
//
// call is the transaction call object (from, to, value, data, etc.) as
// a map[string]interface{} matching the provider's JSON shape. The RPC
// method returns the gas estimate as a hex quantity string per
// [EIP-1474]; it is parsed via rpc.ParseBlockNumber, which rejects
// malformed input and guards against uint64 overflow.
//
// RPC errors from the client are wrapped with fmt.Errorf and %w so
// callers can recover the underlying *rpc.RPCError via errors.As.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
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

// FetchFees returns the current base fee and priority fee suggestion as
// *big.Int values.
//
// The priority fee is obtained from eth_maxPriorityFeePerGas per
// [EIP-1559]. The base fee is obtained from eth_gasPrice per
// [EIP-1474]; on EIP-1559 chains gasPrice reflects the base fee plus a
// provider-suggested tip, while on legacy chains it is the sole fee
// component. Both hex quantity strings are parsed via
// rpc.ParseQuantity, which rejects malformed input (empty string,
// missing 0x prefix, leading zeros, non-hex digits).
//
// RPC errors from the client are wrapped with fmt.Errorf and %w so
// callers can recover the underlying *rpc.RPCError via errors.As. If
// either RPC call fails, the other is not attempted.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
// [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559
func FetchFees(ctx context.Context, client rpc.Client) (baseFee, priorityFee *big.Int, err error) {
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
	baseHex, err := client.GasPrice(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("broadcast: gas price: %w", err)
	}
	baseFee, err = rpc.ParseQuantity(baseHex)
	if err != nil {
		return nil, nil, fmt.Errorf("broadcast: parse base fee: %w", err)
	}
	return baseFee, priorityFee, nil
}
