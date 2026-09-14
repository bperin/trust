package broadcast_test

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/bperin/trust/chain/broadcast"
	"github.com/bperin/trust/chain/rpc"
)

// mockFeeClient is an in-memory rpc.Client for testing the fee/nonce
// helpers. It records calls and returns canned responses. All mutable
// state is guarded by a mutex so the mock is safe under the race
// detector. Methods not exercised by the fee helpers panic, keeping
// the mock focused.
type mockFeeClient struct {
	mu sync.Mutex

	// nonceHex / nonceErr are returned by GetTransactionCount.
	nonceHex string
	nonceErr error
	// nonceAddr records the address passed to GetTransactionCount.
	nonceAddr  string
	nonceBlock string
	// nonceCalls counts GetTransactionCount invocations so tests can
	// assert an invalid block tag never reaches the wire.
	nonceCalls int

	// gasHex / gasErr are returned by EstimateGas.
	gasHex string
	gasErr error
	// gasCall records the call object passed to EstimateGas.
	gasCall map[string]interface{}

	// priorityHex / priorityErr are returned by MaxPriorityFeePerGas.
	priorityHex string
	priorityErr error

	// gasPriceHex / gasPriceErr are returned by GasPrice.
	gasPriceHex string
	gasPriceErr error
	// gasPriceCalls counts GasPrice invocations.
	gasPriceCalls int
}

func (m *mockFeeClient) ChainID(ctx context.Context) (string, error) {
	return "", errors.New("mockFeeClient: ChainID not implemented")
}

func (m *mockFeeClient) GetTransactionCount(ctx context.Context, addr string, blockTag string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonceCalls++
	m.nonceAddr = addr
	m.nonceBlock = blockTag
	if m.nonceErr != nil {
		return "", m.nonceErr
	}
	return m.nonceHex, nil
}

func (m *mockFeeClient) EstimateGas(ctx context.Context, tx map[string]interface{}) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gasCall = tx
	if m.gasErr != nil {
		return "", m.gasErr
	}
	return m.gasHex, nil
}

func (m *mockFeeClient) GasPrice(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gasPriceCalls++
	if m.gasPriceErr != nil {
		return "", m.gasPriceErr
	}
	return m.gasPriceHex, nil
}

func (m *mockFeeClient) MaxPriorityFeePerGas(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.priorityErr != nil {
		return "", m.priorityErr
	}
	return m.priorityHex, nil
}

func (m *mockFeeClient) FeeHistory(ctx context.Context, blockCount string, newestBlock string, rewardPercentiles []float64) (interface{}, error) {
	return nil, errors.New("mockFeeClient: FeeHistory not implemented")
}

func (m *mockFeeClient) SendRawTransaction(ctx context.Context, rawTx string) (string, error) {
	return "", errors.New("mockFeeClient: SendRawTransaction not implemented")
}

func (m *mockFeeClient) GetTransactionReceipt(ctx context.Context, txHash string) (interface{}, error) {
	return nil, errors.New("mockFeeClient: GetTransactionReceipt not implemented")
}

func (m *mockFeeClient) GetTransactionByHash(ctx context.Context, txHash string) (interface{}, error) {
	return nil, errors.New("mockFeeClient: GetTransactionByHash not implemented")
}

// TestFetchNonce verifies FetchNonce forwards the caller-supplied
// block tag to GetTransactionCount verbatim and parses the hex result
// into a uint64.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestFetchNonce(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		address  string
		blockTag string
		nonce    string
		want     uint64
	}{
		{name: "pending tag", address: "0x" + repeat("00", 20), blockTag: "pending", nonce: "0x0", want: 0},
		{name: "latest tag", address: "0x" + repeat("11", 20), blockTag: "latest", nonce: "0x1", want: 1},
		{name: "earliest tag", address: "0x" + repeat("22", 20), blockTag: "earliest", nonce: "0x1c8", want: 456},
		{name: "safe tag", address: "0x" + repeat("33", 20), blockTag: "safe", nonce: "0x5208", want: 0x5208},
		{name: "finalized tag", address: "0x" + repeat("55", 20), blockTag: "finalized", nonce: "0x2", want: 2},
		{name: "hex block number", address: "0x" + repeat("66", 20), blockTag: "0x112a880", nonce: "0x9", want: 9},
		{name: "max uint64", address: "0x" + repeat("44", 20), blockTag: "pending", nonce: "0xffffffffffffffff", want: ^uint64(0)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mc := &mockFeeClient{nonceHex: tc.nonce}
			got, err := broadcast.FetchNonce(context.Background(), mc, tc.address, tc.blockTag)
			if err != nil {
				t.Fatalf("FetchNonce: unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("FetchNonce: got=%d want=%d", got, tc.want)
			}
			mc.mu.Lock()
			defer mc.mu.Unlock()
			if mc.nonceAddr != tc.address {
				t.Fatalf("FetchNonce: address got=%q want=%q", mc.nonceAddr, tc.address)
			}
			if mc.nonceBlock != tc.blockTag {
				t.Fatalf("FetchNonce: blockTag got=%q want=%q", mc.nonceBlock, tc.blockTag)
			}
		})
	}
}

// TestFetchNonceInvalidBlockTag verifies FetchNonce rejects an empty
// or unrecognized block tag with ErrInvalidBlockTag instead of
// silently defaulting to "latest", and that no RPC is issued for a
// rejected tag.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestFetchNonceInvalidBlockTag(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		blockTag string
	}{
		{name: "empty tag", blockTag: ""},
		{name: "unknown word", blockTag: "newest"},
		{name: "numeric without 0x", blockTag: "123"},
		{name: "bare 0x prefix", blockTag: "0x"},
		{name: "invalid hex", blockTag: "0xZZ"},
		{name: "leading zeros", blockTag: "0x0123"},
		{name: "whitespace", blockTag: " latest"},
		{name: "uppercase named tag", blockTag: "LATEST"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mc := &mockFeeClient{nonceHex: "0x1c8"}
			got, err := broadcast.FetchNonce(context.Background(), mc, "0x"+repeat("ab", 20), tc.blockTag)
			if err == nil {
				t.Fatalf("FetchNonce: blockTag %q should error, got nonce %d", tc.blockTag, got)
			}
			if !errors.Is(err, broadcast.ErrInvalidBlockTag) {
				t.Fatalf("FetchNonce: got error %v, want errors.Is(ErrInvalidBlockTag)", err)
			}
			if got != 0 {
				t.Fatalf("FetchNonce: want 0 on error, got=%d", got)
			}
			mc.mu.Lock()
			defer mc.mu.Unlock()
			if mc.nonceCalls != 0 {
				t.Fatalf("FetchNonce: GetTransactionCount called %d times, want 0 for invalid tag %q", mc.nonceCalls, tc.blockTag)
			}
		})
	}
}

// TestFetchNonceNegative verifies FetchNonce surfaces errors for RPC
// failures, malformed hex, and empty responses.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestFetchNonceNegative(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		nonceHex string
		nonceErr error
		wantErr  error // checked via errors.Is when non-nil
		wantRPC  bool  // when true, assert error wraps *rpc.RPCError
	}{
		{name: "rpc error wraps RPCError", nonceErr: &rpc.RPCError{Code: -32000, Message: "rate limited"}, wantRPC: true},
		{name: "generic rpc error", nonceErr: errors.New("connection reset")},
		{name: "empty response", nonceHex: "", wantErr: rpc.ErrEmptyQuantity},
		{name: "missing 0x prefix", nonceHex: "1c8", wantErr: rpc.ErrMissingPrefix},
		{name: "no digits after prefix", nonceHex: "0x", wantErr: rpc.ErrNoDigits},
		{name: "leading zeros", nonceHex: "0x0123", wantErr: rpc.ErrLeadingZeros},
		{name: "invalid hex", nonceHex: "0xzz", wantErr: rpc.ErrInvalidHex},
		{name: "overflow uint64", nonceHex: "0x10000000000000000", wantErr: rpc.ErrBlockNumberOverflow},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mc := &mockFeeClient{nonceHex: tc.nonceHex, nonceErr: tc.nonceErr}
			got, err := broadcast.FetchNonce(context.Background(), mc, "0x"+repeat("ab", 20), "pending")
			if err == nil {
				t.Fatalf("FetchNonce: want error, got nil (nonce=%q)", tc.nonceHex)
			}
			if tc.wantRPC {
				var rpcErr *rpc.RPCError
				if !errors.As(err, &rpcErr) {
					t.Fatalf("FetchNonce: error does not wrap *rpc.RPCError, got %v", err)
				}
				if rpcErr.Code != -32000 {
					t.Fatalf("FetchNonce: code got=%d want=-32000", rpcErr.Code)
				}
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("FetchNonce: error got=%v, want errors.Is(%v)", err, tc.wantErr)
			}
			if got != 0 {
				t.Fatalf("FetchNonce: want 0 on error, got=%d", got)
			}
		})
	}
}

// TestFetchNonceCancelledContext verifies a cancelled context propagates
// the context error when the RPC client honors it.
func TestFetchNonceCancelledContext(t *testing.T) {
	t.Parallel()

	mc := &mockFeeClient{nonceErr: context.Canceled}
	_, err := broadcast.FetchNonce(context.Background(), mc, "0x"+repeat("ab", 20), "pending")
	if err == nil {
		t.Fatal("FetchNonce: want error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("FetchNonce: error got=%v, want errors.Is(context.Canceled)", err)
	}
}

// TestFetchNonceNilClient verifies FetchNonce rejects a nil client.
func TestFetchNonceNilClient(t *testing.T) {
	t.Parallel()
	_, err := broadcast.FetchNonce(context.Background(), nil, "0x"+repeat("ab", 20), "pending")
	if err == nil {
		t.Fatal("FetchNonce: nil client should error")
	}
}

// TestEstimateGasLimit verifies EstimateGasLimit calls EstimateGas with
// the call object and parses the hex result into a uint64.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestEstimateGasLimit(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		gas  string
		call map[string]interface{}
		want uint64
	}{
		{name: "zero gas", gas: "0x0", call: map[string]interface{}{"to": "0x0"}, want: 0},
		{name: "21000 gas", gas: "0x5208", call: map[string]interface{}{"to": "0x0", "value": "0x0"}, want: 21000},
		{name: "large gas", gas: "0x1c8", call: map[string]interface{}{"to": "0x0", "data": "0x"}, want: 456},
		{name: "max uint64", gas: "0xffffffffffffffff", call: map[string]interface{}{}, want: ^uint64(0)},
		{name: "nil call map", gas: "0x1", call: nil, want: 1},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mc := &mockFeeClient{gasHex: tc.gas}
			got, err := broadcast.EstimateGasLimit(context.Background(), mc, tc.call)
			if err != nil {
				t.Fatalf("EstimateGasLimit: unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("EstimateGasLimit: got=%d want=%d", got, tc.want)
			}
			mc.mu.Lock()
			defer mc.mu.Unlock()
			if mc.gasCall == nil && tc.call != nil {
				t.Fatalf("EstimateGasLimit: call not recorded (want %v)", tc.call)
			}
		})
	}
}

// TestEstimateGasLimitNegative verifies EstimateGasLimit surfaces errors
// for RPC failures, malformed hex, and empty responses.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestEstimateGasLimitNegative(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		gasHex  string
		gasErr  error
		wantErr error
		wantRPC bool
	}{
		{name: "rpc error wraps RPCError", gasErr: &rpc.RPCError{Code: -32000, Message: "execution reverted"}, wantRPC: true},
		{name: "generic rpc error", gasErr: errors.New("timeout")},
		{name: "empty response", gasHex: "", wantErr: rpc.ErrEmptyQuantity},
		{name: "missing 0x prefix", gasHex: "5208", wantErr: rpc.ErrMissingPrefix},
		{name: "no digits after prefix", gasHex: "0x", wantErr: rpc.ErrNoDigits},
		{name: "leading zeros", gasHex: "0x05208", wantErr: rpc.ErrLeadingZeros},
		{name: "invalid hex", gasHex: "0xgg", wantErr: rpc.ErrInvalidHex},
		{name: "overflow uint64", gasHex: "0x10000000000000000", wantErr: rpc.ErrBlockNumberOverflow},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mc := &mockFeeClient{gasHex: tc.gasHex, gasErr: tc.gasErr}
			got, err := broadcast.EstimateGasLimit(context.Background(), mc, map[string]interface{}{"to": "0x0"})
			if err == nil {
				t.Fatalf("EstimateGasLimit: want error, got nil (gas=%q)", tc.gasHex)
			}
			if tc.wantRPC {
				var rpcErr *rpc.RPCError
				if !errors.As(err, &rpcErr) {
					t.Fatalf("EstimateGasLimit: error does not wrap *rpc.RPCError, got %v", err)
				}
				if rpcErr.Code != -32000 {
					t.Fatalf("EstimateGasLimit: code got=%d want=-32000", rpcErr.Code)
				}
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("EstimateGasLimit: error got=%v, want errors.Is(%v)", err, tc.wantErr)
			}
			if got != 0 {
				t.Fatalf("EstimateGasLimit: want 0 on error, got=%d", got)
			}
		})
	}
}

// TestEstimateGasLimitCancelledContext verifies a cancelled context
// propagates the context error.
func TestEstimateGasLimitCancelledContext(t *testing.T) {
	t.Parallel()

	mc := &mockFeeClient{gasErr: context.Canceled}
	_, err := broadcast.EstimateGasLimit(context.Background(), mc, map[string]interface{}{"to": "0x0"})
	if err == nil {
		t.Fatal("EstimateGasLimit: want error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("EstimateGasLimit: error got=%v, want errors.Is(context.Canceled)", err)
	}
}

// TestEstimateGasLimitNilClient verifies EstimateGasLimit rejects a nil
// client.
func TestEstimateGasLimitNilClient(t *testing.T) {
	t.Parallel()
	_, err := broadcast.EstimateGasLimit(context.Background(), nil, map[string]interface{}{"to": "0x0"})
	if err == nil {
		t.Fatal("EstimateGasLimit: nil client should error")
	}
}

// TestFetchFees verifies FetchFees returns the eth_gasPrice result and
// the eth_maxPriorityFeePerGas result as *big.Int values parsed from
// their hex quantities. The first return is the gas price — the
// provider's suggested total per-gas price — not the protocol base
// fee.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
// [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559
func TestFetchFees(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		gasPriceHex  string
		priorityHex  string
		wantGasPrice *big.Int
		wantPriority *big.Int
	}{
		{name: "zero fees", gasPriceHex: "0x0", priorityHex: "0x0", wantGasPrice: big.NewInt(0), wantPriority: big.NewInt(0)},
		{name: "1 gwei price 1 gwei tip", gasPriceHex: "0x3b9aca00", priorityHex: "0x3b9aca00", wantGasPrice: big.NewInt(1_000_000_000), wantPriority: big.NewInt(1_000_000_000)},
		{name: "price 10 gwei tip 2 gwei", gasPriceHex: "0x2540be400", priorityHex: "0x77359400", wantGasPrice: big.NewInt(10_000_000_000), wantPriority: big.NewInt(2_000_000_000)},
		{name: "large gas price", gasPriceHex: "0x9184e72a000", priorityHex: "0x1", wantGasPrice: mustBig("0x9184e72a000"), wantPriority: big.NewInt(1)},
		{name: "exceeds uint64 gas price", gasPriceHex: "0x10000000000000000", priorityHex: "0x2", wantGasPrice: mustBig("0x10000000000000000"), wantPriority: big.NewInt(2)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mc := &mockFeeClient{gasPriceHex: tc.gasPriceHex, priorityHex: tc.priorityHex}
			gasPrice, priority, err := broadcast.FetchFees(context.Background(), mc)
			if err != nil {
				t.Fatalf("FetchFees: unexpected error: %v", err)
			}
			if gasPrice == nil {
				t.Fatal("FetchFees: gas price is nil")
			}
			if priority == nil {
				t.Fatal("FetchFees: priority fee is nil")
			}
			if gasPrice.Cmp(tc.wantGasPrice) != 0 {
				t.Fatalf("FetchFees: gas price got=%s want=%s", gasPrice.String(), tc.wantGasPrice.String())
			}
			if priority.Cmp(tc.wantPriority) != 0 {
				t.Fatalf("FetchFees: priority got=%s want=%s", priority.String(), tc.wantPriority.String())
			}
		})
	}
}

// TestFetchFeesGasPriceVerbatim verifies the first FetchFees return
// carries the eth_gasPrice result unchanged — it is the suggested gas
// price, never relabeled or recomputed as a base fee, and it does not
// come from eth_feeHistory (the mock's FeeHistory panics if called).
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestFetchFeesGasPriceVerbatim(t *testing.T) {
	t.Parallel()

	// A gas price of 12 gwei where the tip is 2 gwei: the protocol
	// base fee would be ~10 gwei, so returning exactly the gasPrice
	// result proves no base-fee derivation happens.
	mc := &mockFeeClient{gasPriceHex: "0x2cb417800", priorityHex: "0x77359400"} // 12 gwei, 2 gwei
	gasPrice, priority, err := broadcast.FetchFees(context.Background(), mc)
	if err != nil {
		t.Fatalf("FetchFees: unexpected error: %v", err)
	}
	if want := big.NewInt(12_000_000_000); gasPrice.Cmp(want) != 0 {
		t.Fatalf("FetchFees: gas price got=%s want=%s (eth_gasPrice result verbatim)", gasPrice.String(), want.String())
	}
	if want := big.NewInt(2_000_000_000); priority.Cmp(want) != 0 {
		t.Fatalf("FetchFees: priority got=%s want=%s", priority.String(), want.String())
	}
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if mc.gasPriceCalls != 1 {
		t.Fatalf("FetchFees: GasPrice called %d times, want 1", mc.gasPriceCalls)
	}
}

// TestFetchFeesNegative verifies FetchFees surfaces errors for RPC
// failures, malformed hex, and empty responses on both the priority
// fee and gas price paths.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestFetchFeesNegative(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		gasPriceHex string
		priorityHex string
		gasPriceErr error
		priorityErr error
		wantErr     error
		wantRPC     bool
	}{
		// Priority fee path failures (gas price path not reached).
		{name: "priority rpc error wraps RPCError", priorityErr: &rpc.RPCError{Code: -32001, Message: "method not found"}, wantRPC: true},
		{name: "priority generic error", priorityErr: errors.New("network down")},
		{name: "priority empty response", priorityHex: "", wantErr: rpc.ErrEmptyQuantity},
		{name: "priority missing prefix", priorityHex: "3b9aca00", wantErr: rpc.ErrMissingPrefix},
		{name: "priority no digits", priorityHex: "0x", wantErr: rpc.ErrNoDigits},
		{name: "priority leading zeros", priorityHex: "0x03b9aca00", wantErr: rpc.ErrLeadingZeros},
		{name: "priority invalid hex", priorityHex: "0xzz", wantErr: rpc.ErrInvalidHex},
		// Gas price path failures (priority fee succeeds).
		{name: "gas price rpc error wraps RPCError", priorityHex: "0x1", gasPriceErr: &rpc.RPCError{Code: -32000, Message: "gas price unavailable"}, wantRPC: true},
		{name: "gas price generic error", priorityHex: "0x1", gasPriceErr: errors.New("timeout")},
		{name: "gas price empty response", priorityHex: "0x1", gasPriceHex: "", wantErr: rpc.ErrEmptyQuantity},
		{name: "gas price missing prefix", priorityHex: "0x1", gasPriceHex: "2540be400", wantErr: rpc.ErrMissingPrefix},
		{name: "gas price no digits", priorityHex: "0x1", gasPriceHex: "0x", wantErr: rpc.ErrNoDigits},
		{name: "gas price leading zeros", priorityHex: "0x1", gasPriceHex: "0x02540be400", wantErr: rpc.ErrLeadingZeros},
		{name: "gas price invalid hex", priorityHex: "0x1", gasPriceHex: "0xgg", wantErr: rpc.ErrInvalidHex},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mc := &mockFeeClient{
				gasPriceHex: tc.gasPriceHex,
				priorityHex: tc.priorityHex,
				gasPriceErr: tc.gasPriceErr,
				priorityErr: tc.priorityErr,
			}
			gasPrice, priority, err := broadcast.FetchFees(context.Background(), mc)
			if err == nil {
				t.Fatalf("FetchFees: want error, got nil (gasPrice=%q priority=%q)", tc.gasPriceHex, tc.priorityHex)
			}
			if tc.wantRPC {
				var rpcErr *rpc.RPCError
				if !errors.As(err, &rpcErr) {
					t.Fatalf("FetchFees: error does not wrap *rpc.RPCError, got %v", err)
				}
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("FetchFees: error got=%v, want errors.Is(%v)", err, tc.wantErr)
			}
			if gasPrice != nil {
				t.Fatalf("FetchFees: want nil gas price on error, got %s", gasPrice.String())
			}
			if priority != nil {
				t.Fatalf("FetchFees: want nil priority on error, got %s", priority.String())
			}
		})
	}
}

// TestFetchFeesCancelledContext verifies a cancelled context propagates
// the context error.
func TestFetchFeesCancelledContext(t *testing.T) {
	t.Parallel()

	mc := &mockFeeClient{priorityErr: context.Canceled}
	_, _, err := broadcast.FetchFees(context.Background(), mc)
	if err == nil {
		t.Fatal("FetchFees: want error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("FetchFees: error got=%v, want errors.Is(context.Canceled)", err)
	}
}

// TestFetchFeesNilClient verifies FetchFees rejects a nil client.
func TestFetchFeesNilClient(t *testing.T) {
	t.Parallel()
	_, _, err := broadcast.FetchFees(context.Background(), nil)
	if err == nil {
		t.Fatal("FetchFees: nil client should error")
	}
}

// TestRaceFetchFeesConcurrent runs the fee helpers concurrently to
// stress the race detector. Each goroutine uses its own mock so there
// is no shared mutable state across goroutines.
func TestRaceFetchFeesConcurrent(t *testing.T) {
	t.Parallel()

	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			mc := &mockFeeClient{
				nonceHex:    "0x1c8",
				gasHex:      "0x5208",
				gasPriceHex: "0x3b9aca00",
				priorityHex: "0x1",
			}
			nonce, err := broadcast.FetchNonce(context.Background(), mc, "0x"+repeat("ab", 20), "pending")
			if err != nil {
				panic("FetchNonce: " + err.Error())
			}
			if nonce != 456 {
				panic("FetchNonce: bad nonce")
			}
			gas, err := broadcast.EstimateGasLimit(context.Background(), mc, map[string]interface{}{"to": "0x0"})
			if err != nil {
				panic("EstimateGasLimit: " + err.Error())
			}
			if gas != 0x5208 {
				panic("EstimateGasLimit: bad gas")
			}
			gasPrice, priority, err := broadcast.FetchFees(context.Background(), mc)
			if err != nil {
				panic("FetchFees: " + err.Error())
			}
			if gasPrice.Cmp(big.NewInt(1_000_000_000)) != 0 {
				panic("FetchFees: bad gas price")
			}
			if priority.Cmp(big.NewInt(1)) != 0 {
				panic("FetchFees: bad priority")
			}
		}()
	}
	wg.Wait()
}

// mustBig parses a hex string (with 0x prefix) into a *big.Int. It
// panics on failure, which is acceptable in test setup for known-good
// constants.
func mustBig(hex string) *big.Int {
	n, ok := new(big.Int).SetString(hex, 0)
	if !ok {
		panic("mustBig: invalid hex " + hex)
	}
	return n
}

// repeat returns s concatenated n times. Used to build 20-byte hex
// addresses in test cases without importing encoding/hex.
func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
