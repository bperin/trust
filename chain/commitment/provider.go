package commitment

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/bperin/trust/chain/abi"
	"github.com/bperin/trust/chain/broadcast"
	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/rpc"
)

// RootSignature is the canonical Solidity signature of the root()
// accessor the commitment contract exposes for on-chain Merkle-root
// reads via eth_call.
const RootSignature = "root()"

// Provider is the consumer-side abstraction over an EVM RPC endpoint
// for publishing and verifying commitments. The four methods cover
// broadcast, receipt polling, head height, and on-chain root reads.
type Provider interface {
	// SendTx broadcasts a signed raw transaction and returns its hash.
	SendTx(ctx context.Context, rawTx []byte) (string, error)
	// Receipt polls until the transaction is mined and returns the
	// typed receipt, or fails on context cancellation.
	Receipt(ctx context.Context, txHash string) (*Receipt, error)
	// BlockNumber returns the current head block number.
	BlockNumber(ctx context.Context) (uint64, error)
	// Root reads the 32-byte Merkle root stored at contract via an
	// eth_call to root() at the given block tag.
	Root(ctx context.Context, contract ethereum.Address, blockTag string) ([32]byte, error)
}

// RPCClient is the transport interface NewRPCProvider accepts: the
// nine-method rpc.Client plus BlockNumber and Call, which *rpc.HTTPClient
// satisfies. Consumer-side tests substitute a fake implementing this.
type RPCClient interface {
	rpc.Client
	BlockNumber(ctx context.Context) (string, error)
	Call(ctx context.Context, call map[string]interface{}, blockTag string) (string, error)
}

// RPCProvider adapts an RPCClient to the Provider interface. It
// delegates broadcast and receipt polling to chain/broadcast and
// adds typed BlockNumber and Root helpers.
type RPCProvider struct {
	client       RPCClient
	pollInterval time.Duration
}

// ProviderOption configures an RPCProvider.
type ProviderOption func(*RPCProvider)

// WithPollInterval sets the receipt poll interval. A non-positive
// duration is ignored, leaving the default in place.
func WithPollInterval(d time.Duration) ProviderOption {
	return func(p *RPCProvider) {
		if d > 0 {
			p.pollInterval = d
		}
	}
}

// NewRPCProvider returns an RPCProvider backed by c with the default
// poll interval applied before options. A nil c is allowed; each
// method guards against it and returns a wrapped error on use.
func NewRPCProvider(c RPCClient, opts ...ProviderOption) *RPCProvider {
	p := &RPCProvider{
		client:       c,
		pollInterval: broadcast.DefaultPollInterval,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// SendTx broadcasts a signed raw transaction via eth_sendRawTransaction.
func (p *RPCProvider) SendTx(ctx context.Context, rawTx []byte) (string, error) {
	if p.client == nil {
		return "", fmt.Errorf("commitment: nil rpc client")
	}
	hash, err := broadcast.SendTx(ctx, p.client, rawTx)
	if err != nil {
		return "", fmt.Errorf("commitment: send tx: %w", err)
	}
	return hash, nil
}

// Receipt polls eth_getTransactionReceipt until the transaction is
// mined or the context is cancelled.
func (p *RPCProvider) Receipt(ctx context.Context, txHash string) (*Receipt, error) {
	if p.client == nil {
		return nil, fmt.Errorf("commitment: nil rpc client")
	}
	r, err := broadcast.WaitForReceipt(ctx, p.client, txHash, broadcast.WithPollInterval(p.pollInterval))
	if err != nil {
		return nil, fmt.Errorf("commitment: receipt: %w", err)
	}
	return r, nil
}

// BlockNumber returns the current head block number as a uint64.
func (p *RPCProvider) BlockNumber(ctx context.Context) (uint64, error) {
	if p.client == nil {
		return 0, fmt.Errorf("commitment: nil rpc client")
	}
	hexStr, err := p.client.BlockNumber(ctx)
	if err != nil {
		return 0, fmt.Errorf("commitment: block number: %w", err)
	}
	n, err := rpc.ParseBlockNumber(hexStr)
	if err != nil {
		return 0, fmt.Errorf("commitment: parse block number: %w", err)
	}
	return n, nil
}

// Root reads the 32-byte Merkle root stored at contract by calling
// root() via eth_call at blockTag. A result that is not exactly 32
// bytes yields ErrRootGetterFailed.
func (p *RPCProvider) Root(ctx context.Context, contract ethereum.Address, blockTag string) ([32]byte, error) {
	var out [32]byte
	if p.client == nil {
		return out, fmt.Errorf("commitment: nil rpc client")
	}
	selector := abi.FunctionSelector(RootSignature)
	call := map[string]interface{}{
		"to":   contract.Hex(),
		"data": "0x" + hex.EncodeToString(selector[:]),
	}
	res, err := p.client.Call(ctx, call, blockTag)
	if err != nil {
		return out, fmt.Errorf("commitment: eth_call root: %w", err)
	}
	body := strings.TrimPrefix(res, "0x")
	decoded, err := hex.DecodeString(body)
	if err != nil {
		return out, fmt.Errorf("commitment: decode root: %w", err)
	}
	if len(decoded) != 32 {
		return out, fmt.Errorf("commitment: %w: got %d bytes, want 32", ErrRootGetterFailed, len(decoded))
	}
	copy(out[:], decoded)
	return out, nil
}

// Compile-time interface check.
var _ Provider = (*RPCProvider)(nil)
