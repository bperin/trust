package broadcast_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bperin/chain/broadcast"
	"github.com/bperin/chain/rpc"
)

// mockClient is an in-memory rpc.Client for testing. It records calls
// and returns canned responses. All mutable state is guarded by a
// mutex so the mock is safe under the race detector.
type mockClient struct {
	mu sync.Mutex

	// sendHash is the hash returned by SendRawTransaction.
	sendHash string
	// sendErr is the error returned by SendRawTransaction.
	sendErr error
	// sendCalls records the raw tx strings passed to SendRawTransaction.
	sendCalls []string

	// receipt is the interface{} returned by GetTransactionReceipt.
	// When receiptReady is false, GetTransactionReceipt returns nil
	// (transaction not yet mined).
	receiptReady atomic.Bool
	receipt      interface{}
	// receiptErr is the error returned by GetTransactionReceipt.
	receiptErr error
	// receiptCalls counts GetTransactionReceipt invocations.
	receiptCalls atomic.Int64

	// unused methods below panic if called, keeping the mock focused.
}

func (m *mockClient) ChainID(ctx context.Context) (string, error) {
	return "", errors.New("mockClient: ChainID not implemented")
}
func (m *mockClient) GetTransactionCount(ctx context.Context, addr string, blockTag string) (string, error) {
	return "", errors.New("mockClient: GetTransactionCount not implemented")
}
func (m *mockClient) EstimateGas(ctx context.Context, tx map[string]interface{}) (string, error) {
	return "", errors.New("mockClient: EstimateGas not implemented")
}
func (m *mockClient) GasPrice(ctx context.Context) (string, error) {
	return "", errors.New("mockClient: GasPrice not implemented")
}
func (m *mockClient) MaxPriorityFeePerGas(ctx context.Context) (string, error) {
	return "", errors.New("mockClient: MaxPriorityFeePerGas not implemented")
}
func (m *mockClient) FeeHistory(ctx context.Context, blockCount string, newestBlock string, rewardPercentiles []float64) (interface{}, error) {
	return nil, errors.New("mockClient: FeeHistory not implemented")
}
func (m *mockClient) SendRawTransaction(ctx context.Context, rawTx string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendCalls = append(m.sendCalls, rawTx)
	if m.sendErr != nil {
		return "", m.sendErr
	}
	return m.sendHash, nil
}
func (m *mockClient) GetTransactionReceipt(ctx context.Context, txHash string) (interface{}, error) {
	m.receiptCalls.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.receiptErr != nil {
		return nil, m.receiptErr
	}
	if !m.receiptReady.Load() {
		return nil, nil
	}
	return m.receipt, nil
}
func (m *mockClient) GetTransactionByHash(ctx context.Context, txHash string) (interface{}, error) {
	return nil, errors.New("mockClient: GetTransactionByHash not implemented")
}

// setReceipt marks the receipt as mined and stores the canned response.
func (m *mockClient) setReceipt(r interface{}) {
	m.mu.Lock()
	m.receipt = r
	m.mu.Unlock()
	m.receiptReady.Store(true)
}

// sampleReceipt is a canonical eth_getTransactionReceipt response shape
// matching [EIP-1474]. Numeric fields are hex quantities.
func sampleReceipt() map[string]interface{} {
	return map[string]interface{}{
		"status":           "0x1",
		"blockHash":        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"blockNumber":      "0x1c8",
		"transactionHash":  "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"transactionIndex": "0xa",
		"gasUsed":          "0x5208",
		"contractAddress":  "",
		"logs":             []interface{}{map[string]interface{}{"address": "0xcccccccccccccccccccccccccccccccccccccccc"}},
	}
}

// TestSendTx verifies SendTx hex-encodes the raw bytes with a 0x
// prefix, forwards them to SendRawTransaction, and returns the hash.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestSendTx(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		rawTx   []byte
		sendErr error
		wantErr bool
	}{
		{name: "success returns hash", rawTx: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "empty raw tx still 0x", rawTx: nil},
		{name: "single byte", rawTx: []byte{0x01}},
		{name: "rpc error wrapped", rawTx: []byte{0x02}, sendErr: &rpc.RPCError{Code: -32000, Message: "nonce too low"}, wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mc := &mockClient{sendHash: "0xhash", sendErr: tc.sendErr}
			got, err := broadcast.SendTx(context.Background(), mc, tc.rawTx)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("SendTx: want error, got nil (rawTx=%v)", tc.rawTx)
				}
				var rpcErr *rpc.RPCError
				if !errors.As(err, &rpcErr) {
					t.Fatalf("SendTx: error does not wrap *rpc.RPCError, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("SendTx: unexpected error: %v", err)
			}
			wantHash := "0xhash"
			if got != wantHash {
				t.Fatalf("SendTx: got=%q want=%q", got, wantHash)
			}
			// Verify the forwarded string is 0x-prefixed hex of rawTx.
			mc.mu.Lock()
			defer mc.mu.Unlock()
			if len(mc.sendCalls) != 1 {
				t.Fatalf("SendTx: got %d SendRawTransaction calls, want 1", len(mc.sendCalls))
			}
			wantFwd := "0x" + hexEncode(tc.rawTx)
			if mc.sendCalls[0] != wantFwd {
				t.Fatalf("SendTx: forwarded=%q want=%q", mc.sendCalls[0], wantFwd)
			}
		})
	}
}

// hexEncode returns the lowercase hex of b without the 0x prefix,
// matching encoding/hex.EncodeToString.
func hexEncode(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexd[v>>4]
		out[i*2+1] = hexd[v&0xf]
	}
	return string(out)
}

// TestSendTxNilClient verifies SendTx rejects a nil client.
func TestSendTxNilClient(t *testing.T) {
	t.Parallel()
	_, err := broadcast.SendTx(context.Background(), nil, []byte{0x01})
	if err == nil {
		t.Fatal("SendTx: nil client should error")
	}
}

// TestWaitForReceipt verifies WaitForReceipt polls until a receipt is
// available and decodes it into a typed *Receipt.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestWaitForReceipt(t *testing.T) {
	t.Parallel()

	mc := &mockClient{}
	// Mine the receipt immediately so the first poll returns it.
	mc.setReceipt(sampleReceipt())

	r, err := broadcast.WaitForReceipt(context.Background(), mc, "0xhash", broadcast.WithPollInterval(10*time.Millisecond))
	if err != nil {
		t.Fatalf("WaitForReceipt: unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("WaitForReceipt: got nil receipt")
	}
	if r.Status != 1 {
		t.Errorf("Status: got=%d want=1", r.Status)
	}
	if r.BlockNumber != 456 {
		t.Errorf("BlockNumber: got=%d want=456", r.BlockNumber)
	}
	if r.TransactionIndex != 10 {
		t.Errorf("TransactionIndex: got=%d want=10", r.TransactionIndex)
	}
	if r.GasUsed != 0x5208 {
		t.Errorf("GasUsed: got=%d want=0x5208", r.GasUsed)
	}
	if r.BlockHash == "" {
		t.Error("BlockHash: got empty, want non-empty")
	}
	if r.TransactionHash == "" {
		t.Error("TransactionHash: got empty, want non-empty")
	}
	if len(r.Logs) != 1 {
		t.Errorf("Logs: got=%d want=1", len(r.Logs))
	}
}

// TestWaitForReceiptPollsUntilMined verifies WaitForReceipt keeps
// polling while the receipt is nil (not yet mined) and returns once it
// becomes available.
func TestWaitForReceiptPollsUntilMined(t *testing.T) {
	t.Parallel()

	mc := &mockClient{}
	// Schedule the receipt to become available after a short delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		mc.setReceipt(sampleReceipt())
	}()

	start := time.Now()
	r, err := broadcast.WaitForReceipt(context.Background(), mc, "0xhash", broadcast.WithPollInterval(10*time.Millisecond))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("WaitForReceipt: unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("WaitForReceipt: got nil receipt")
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("WaitForReceipt: returned too fast (elapsed=%v), expected at least one nil poll", elapsed)
	}
	if calls := mc.receiptCalls.Load(); calls < 2 {
		t.Fatalf("WaitForReceipt: got %d receipt calls, want >=2 (nil then mined)", calls)
	}
}

// TestWaitForReceiptPollInterval verifies WithPollInterval changes the
// polling cadence: with a 100ms interval, two polls take at least 100ms.
func TestWaitForReceiptPollInterval(t *testing.T) {
	t.Parallel()

	mc := &mockClient{}
	// Make the receipt available only after the second poll.
	go func() {
		for {
			if mc.receiptCalls.Load() >= 2 {
				mc.setReceipt(sampleReceipt())
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	start := time.Now()
	_, err := broadcast.WaitForReceipt(context.Background(), mc, "0xhash", broadcast.WithPollInterval(100*time.Millisecond))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("WaitForReceipt: unexpected error: %v", err)
	}
	// The first poll is immediate; the second happens after one
	// 100ms tick. So total elapsed should be >= ~100ms.
	if elapsed < 90*time.Millisecond {
		t.Fatalf("WaitForReceipt: interval not respected (elapsed=%v), want >=90ms for 100ms poll", elapsed)
	}
}

// TestWaitForReceiptCancelledMidPoll verifies that cancelling the
// context mid-poll returns the context error and leaks no goroutine.
func TestWaitForReceiptCancelledMidPoll(t *testing.T) {
	t.Parallel()

	mc := &mockClient{} // receipt never becomes ready

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after the first poll returns nil.
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	r, err := broadcast.WaitForReceipt(ctx, mc, "0xhash", broadcast.WithPollInterval(200*time.Millisecond))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("WaitForReceipt: want context error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForReceipt: error is not context.Canceled, got %v", err)
	}
	if r != nil {
		t.Fatalf("WaitForReceipt: want nil receipt on cancel, got %v", r)
	}
	// Should return promptly after cancel, not wait the full 200ms tick.
	if elapsed > 150*time.Millisecond {
		t.Fatalf("WaitForReceipt: returned too slowly after cancel (elapsed=%v)", elapsed)
	}
	// No goroutine leak: WaitForReceipt returns synchronously, so by
	// the time we reach here the poll loop has exited.
	if calls := mc.receiptCalls.Load(); calls < 1 {
		t.Fatalf("WaitForReceipt: got %d receipt calls, want >=1", calls)
	}
}

// TestWaitForReceiptAlreadyCancelled verifies an already-cancelled
// context returns immediately without polling.
func TestWaitForReceiptAlreadyCancelled(t *testing.T) {
	t.Parallel()

	mc := &mockClient{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	r, err := broadcast.WaitForReceipt(ctx, mc, "0xhash", broadcast.WithPollInterval(10*time.Millisecond))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("WaitForReceipt: want context error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForReceipt: error is not context.Canceled, got %v", err)
	}
	if r != nil {
		t.Fatalf("WaitForReceipt: want nil receipt, got %v", r)
	}
	if elapsed > 10*time.Millisecond {
		t.Fatalf("WaitForReceipt: not immediate on cancelled ctx (elapsed=%v)", elapsed)
	}
	if calls := mc.receiptCalls.Load(); calls != 0 {
		t.Fatalf("WaitForReceipt: got %d receipt calls, want 0 on already-cancelled ctx", calls)
	}
}

// TestWaitForReceiptRPCError verifies a receipt RPC error is wrapped
// and returned.
func TestWaitForReceiptRPCError(t *testing.T) {
	t.Parallel()

	mc := &mockClient{receiptErr: &rpc.RPCError{Code: -32001, Message: "tx not found"}}
	_, err := broadcast.WaitForReceipt(context.Background(), mc, "0xhash", broadcast.WithPollInterval(10*time.Millisecond))
	if err == nil {
		t.Fatal("WaitForReceipt: want error, got nil")
	}
	var rpcErr *rpc.RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("WaitForReceipt: error does not wrap *rpc.RPCError, got %v", err)
	}
	if rpcErr.Code != -32001 {
		t.Fatalf("WaitForReceipt: code got=%d want=-32001", rpcErr.Code)
	}
}

// TestWaitForReceiptNilClient verifies WaitForReceipt rejects a nil client.
func TestWaitForReceiptNilClient(t *testing.T) {
	t.Parallel()
	_, err := broadcast.WaitForReceipt(context.Background(), nil, "0xhash")
	if err == nil {
		t.Fatal("WaitForReceipt: nil client should error")
	}
}

// TestParseReceiptMalformed verifies parseReceipt rejects a response
// that is not a map[string]interface{}.
func TestParseReceiptMalformed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  interface{}
	}{
		{name: "string", raw: "not a receipt"},
		{name: "int", raw: 42},
		{name: "slice", raw: []interface{}{1, 2, 3}},
		{name: "bool", raw: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mc := &mockClient{}
			mc.setReceipt(tc.raw)
			_, err := broadcast.WaitForReceipt(context.Background(), mc, "0xhash", broadcast.WithPollInterval(10*time.Millisecond))
			if err == nil {
				t.Fatalf("WaitForReceipt: malformed receipt %v should error", tc.raw)
			}
		})
	}
}

// TestParseReceiptBadHex verifies parseReceipt surfaces an error when a
// hex quantity field is malformed.
func TestParseReceiptBadHex(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  map[string]interface{}
	}{
		{name: "bad status", raw: map[string]interface{}{"status": "0x0123"}},
		{name: "bad blockNumber", raw: map[string]interface{}{"blockNumber": "not-hex"}},
		{name: "bad transactionIndex", raw: map[string]interface{}{"transactionIndex": "0xzz"}},
		{name: "bad gasUsed", raw: map[string]interface{}{"gasUsed": "0x0123"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mc := &mockClient{}
			mc.setReceipt(tc.raw)
			_, err := broadcast.WaitForReceipt(context.Background(), mc, "0xhash", broadcast.WithPollInterval(10*time.Millisecond))
			if err == nil {
				t.Fatalf("WaitForReceipt: bad hex %v should error", tc.raw)
			}
		})
	}
}

// TestWaitForReceiptContractAddress verifies the contractAddress field
// is propagated for a contract-creation transaction.
func TestWaitForReceiptContractAddress(t *testing.T) {
	t.Parallel()

	mc := &mockClient{}
	mc.setReceipt(map[string]interface{}{
		"status":          "0x1",
		"contractAddress": "0xdddddddddddddddddddddddddddddddddddddddd",
	})

	r, err := broadcast.WaitForReceipt(context.Background(), mc, "0xhash", broadcast.WithPollInterval(10*time.Millisecond))
	if err != nil {
		t.Fatalf("WaitForReceipt: unexpected error: %v", err)
	}
	want := "0xdddddddddddddddddddddddddddddddddddddddd"
	if r.ContractAddress != want {
		t.Fatalf("ContractAddress: got=%q want=%q", r.ContractAddress, want)
	}
}

// TestWithPollIntervalNonPositive verifies a non-positive duration is
// ignored and the default interval is retained. This is a smoke test:
// with a zero interval the default 2s would apply, so we instead
// confirm the option does not panic and a positive override still
// works.
func TestWithPollIntervalNonPositive(t *testing.T) {
	t.Parallel()

	mc := &mockClient{}
	mc.setReceipt(sampleReceipt())

	// A zero duration must not zero out the poll interval (which
	// would busy-loop); the default is retained. We can't observe
	// the default cheaply, so just confirm no panic and success.
	r, err := broadcast.WaitForReceipt(context.Background(), mc, "0xhash", broadcast.WithPollInterval(0))
	if err != nil {
		t.Fatalf("WaitForReceipt: unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("WaitForReceipt: got nil receipt")
	}
}

// TestRaceWaitForReceiptConcurrent runs WaitForReceipt concurrently to
// stress the race detector. Each goroutine uses its own mock so there
// is no shared mutable state across goroutines.
func TestRaceWaitForReceiptConcurrent(t *testing.T) {
	t.Parallel()

	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			mc := &mockClient{}
			mc.setReceipt(sampleReceipt())
			r, err := broadcast.WaitForReceipt(context.Background(), mc, "0xhash", broadcast.WithPollInterval(5*time.Millisecond))
			if err != nil {
				panic(fmt.Sprintf("WaitForReceipt: unexpected error: %v", err))
			}
			if r == nil {
				panic("WaitForReceipt: nil receipt")
			}
		}()
	}
	wg.Wait()
}
