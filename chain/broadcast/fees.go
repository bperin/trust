package broadcast

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/bperin/trust/chain/rpc"
)

// ErrInvalidBlockTag is returned when a block tag argument is not one
// of the named tags — "latest", "earliest", "pending", "safe",
// "finalized" — or a valid hex block-number quantity per [EIP-1474].
// Checked with errors.Is.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
var ErrInvalidBlockTag = errors.New("broadcast: invalid block tag")

// FetchNonce returns the next transaction nonce for address by calling
// eth_getTransactionCount at the caller-supplied block tag.
//
// blockTag is explicit and mandatory: an empty or unrecognized tag is
// rejected with ErrInvalidBlockTag before any RPC is issued, rather
// than silently defaulting to "latest". Accepted values are the named
// tags — "latest", "earliest", "pending", "safe", "finalized" — or a
// hex block-number quantity ("0x...") per [EIP-1474]. Choose "pending"
// when the nonce must account for transactions already broadcast but
// not yet mined; "latest" counts only mined transactions and can
// undercount when a transaction is in flight.
//
// The RPC method returns the nonce as a hex quantity string per
// [EIP-1474]; it is parsed via rpc.ParseBlockNumber, which rejects
// malformed input (empty string, missing 0x prefix, leading zeros,
// non-hex digits) and guards against uint64 overflow. The result is
// the number of transactions sent from address at that block tag,
// which is the next nonce to use for a new transaction.
//
// RPC errors from the client are wrapped with fmt.Errorf and %w so
// callers can recover the underlying *rpc.RPCError via errors.As.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
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

// validBlockTag reports whether tag is an [EIP-1474] named block tag
// or a hex block-number quantity.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func validBlockTag(tag string) bool {
	switch tag {
	case "latest", "earliest", "pending", "safe", "finalized":
		return true
	}
	_, err := rpc.ParseQuantity(tag)
	return err == nil
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

// FetchFees returns the node's current gas price suggestion and
// priority fee suggestion as *big.Int values.
//
// The gas price is obtained from eth_gasPrice per [EIP-1474]. It is
// labeled gasPrice, not baseFee: on EIP-1559 chains eth_gasPrice
// returns the provider's suggested total per-gas price (protocol base
// fee plus tip), while on legacy chains it is the sole fee component.
// Callers that need the protocol base fee itself must read
// baseFeePerGas from a block or use eth_feeHistory — this function
// does not expose it. The priority fee is obtained from
// eth_maxPriorityFeePerGas per [EIP-1559].
//
// Both hex quantity strings are parsed via rpc.ParseQuantity, which
// rejects malformed input (empty string, missing 0x prefix, leading
// zeros, non-hex digits).
//
// RPC errors from the client are wrapped with fmt.Errorf and %w so
// callers can recover the underlying *rpc.RPCError via errors.As. If
// either RPC call fails, the other is not attempted.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
// [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559
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
