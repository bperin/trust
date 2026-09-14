// Package broadcast composes the send-and-wait flow for EVM
// transactions over a JSON-RPC provider. SendTx broadcasts a signed
// raw transaction via eth_sendRawTransaction, and WaitForReceipt polls
// eth_getTransactionReceipt until the transaction is mined or the
// context is cancelled.
package broadcast

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/bperin/trust/chain/rpc"
)

// DefaultPollInterval is the interval WaitForReceipt polls
// eth_getTransactionReceipt when no WithPollInterval option is supplied.
const DefaultPollInterval = 2 * time.Second

// ErrMalformedReceipt is returned when an eth_getTransactionReceipt
// response is not a JSON object, is missing a required field, or
// carries a field of the wrong type. Checked with errors.Is.
var ErrMalformedReceipt = errors.New("broadcast: malformed receipt")

// requiredReceiptFields lists the receipt fields that must be present
// on a mined transaction receipt.
var requiredReceiptFields = []string{
	"status",
	"blockHash",
	"blockNumber",
	"transactionHash",
	"transactionIndex",
	"gasUsed",
	"contractAddress",
	"logs",
}

// Receipt is the typed form of an eth_getTransactionReceipt response.
type Receipt struct {
	// Status is the execution status: 1 for success, 0 for failure.
	Status uint64
	// BlockHash is the hash of the block that mined the
	// transaction.
	BlockHash string
	// BlockNumber is the height of the block that mined the
	// transaction.
	BlockNumber uint64
	// TransactionHash is the transaction hash.
	TransactionHash string
	// TransactionIndex is the index of the transaction in its
	// block.
	TransactionIndex uint64
	// GasUsed is the gas consumed by the transaction.
	GasUsed uint64
	// ContractAddress is the created contract address, or the
	// empty string when no contract was created.
	ContractAddress string
	// Logs is the list of emitted log entries, passed through
	// untyped for the caller to decode.
	Logs []interface{}
}

// WaitOption is a functional option for WaitForReceipt.
type WaitOption func(*waitConfig)

// waitConfig holds the resolved options for a WaitForReceipt call.
type waitConfig struct {
	pollInterval time.Duration
}

// WithPollInterval sets the interval at which WaitForReceipt polls.
// A non-positive duration is ignored, leaving the default in place.
func WithPollInterval(d time.Duration) WaitOption {
	return func(c *waitConfig) {
		if d > 0 {
			c.pollInterval = d
		}
	}
}

// newWaitConfig builds a waitConfig from the supplied options, applying
// the default poll interval before options run.
func newWaitConfig(opts []WaitOption) waitConfig {
	c := waitConfig{pollInterval: DefaultPollInterval}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// SendTx broadcasts a signed raw transaction via
// eth_sendRawTransaction. rawTx is hex-encoded with a "0x" prefix
// before sending; the returned string is the transaction hash
// reported by the node.
func SendTx(ctx context.Context, client rpc.Client, rawTx []byte) (string, error) {
	if client == nil {
		return "", fmt.Errorf("broadcast: nil rpc client")
	}
	hexStr := "0x" + hex.EncodeToString(rawTx)
	hash, err := client.SendRawTransaction(ctx, hexStr)
	if err != nil {
		return "", fmt.Errorf("broadcast: send raw transaction: %w", err)
	}
	return hash, nil
}

// WaitForReceipt polls eth_getTransactionReceipt until the
// transaction is mined and a receipt is available, or ctx is
// cancelled. A nil receipt response (not yet mined) continues
// polling; the poll interval defaults to DefaultPollInterval.
// Context cancellation is the only timeout.
func WaitForReceipt(ctx context.Context, client rpc.Client, txHash string, opts ...WaitOption) (*Receipt, error) {
	if client == nil {
		return nil, fmt.Errorf("broadcast: nil rpc client")
	}
	cfg := newWaitConfig(opts)

	// An already-cancelled context returns immediately without
	// allocating a ticker.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ticker := time.NewTicker(cfg.pollInterval)
	defer ticker.Stop()

	for {
		raw, err := client.GetTransactionReceipt(ctx, txHash)
		if err != nil {
			return nil, fmt.Errorf("broadcast: get transaction receipt: %w", err)
		}
		if raw != nil {
			return parseReceipt(raw)
		}

		select {
		case <-ticker.C:
			// poll again
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// parseReceipt decodes an eth_getTransactionReceipt response into a
// Receipt. A response that is not a JSON object or is missing a
// required field returns ErrMalformedReceipt.
func parseReceipt(raw interface{}) (*Receipt, error) {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("broadcast: %w: got %T, want object", ErrMalformedReceipt, raw)
	}

	// Every required field must be present before any decoding.
	for _, key := range requiredReceiptFields {
		if _, ok := m[key]; !ok {
			return nil, fmt.Errorf("broadcast: %w: missing required field %q", ErrMalformedReceipt, key)
		}
	}

	r := &Receipt{}

	status, err := receiptString(m, "status")
	if err != nil {
		return nil, err
	}
	r.Status, err = rpc.ParseBlockNumber(status)
	if err != nil {
		return nil, fmt.Errorf("broadcast: %w: parse status: %w", ErrMalformedReceipt, err)
	}

	r.BlockHash, err = receiptString(m, "blockHash")
	if err != nil {
		return nil, err
	}

	blockNumber, err := receiptString(m, "blockNumber")
	if err != nil {
		return nil, err
	}
	r.BlockNumber, err = rpc.ParseBlockNumber(blockNumber)
	if err != nil {
		return nil, fmt.Errorf("broadcast: %w: parse blockNumber: %w", ErrMalformedReceipt, err)
	}

	r.TransactionHash, err = receiptString(m, "transactionHash")
	if err != nil {
		return nil, err
	}

	txIndex, err := receiptString(m, "transactionIndex")
	if err != nil {
		return nil, err
	}
	r.TransactionIndex, err = rpc.ParseBlockNumber(txIndex)
	if err != nil {
		return nil, fmt.Errorf("broadcast: %w: parse transactionIndex: %w", ErrMalformedReceipt, err)
	}

	gasUsed, err := receiptString(m, "gasUsed")
	if err != nil {
		return nil, err
	}
	r.GasUsed, err = rpc.ParseBlockNumber(gasUsed)
	if err != nil {
		return nil, fmt.Errorf("broadcast: %w: parse gasUsed: %w", ErrMalformedReceipt, err)
	}

	// contractAddress is null for transactions that created no
	// contract; some providers emit an empty string instead. Both
	// decode to the empty string.
	switch v := m["contractAddress"].(type) {
	case nil:
		// JSON null: no contract created.
	case string:
		r.ContractAddress = v
	default:
		return nil, fmt.Errorf("broadcast: %w: field %q is %T, want string or null", ErrMalformedReceipt, "contractAddress", v)
	}

	logs, ok := m["logs"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("broadcast: %w: field %q is %T, want array", ErrMalformedReceipt, "logs", m["logs"])
	}
	r.Logs = logs

	return r, nil
}

// receiptString returns field key of m as a non-empty string, or an
// error wrapping ErrMalformedReceipt.
func receiptString(m map[string]interface{}, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("broadcast: %w: missing required field %q", ErrMalformedReceipt, key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("broadcast: %w: field %q is %v, want non-empty string", ErrMalformedReceipt, key, v)
	}
	return s, nil
}
