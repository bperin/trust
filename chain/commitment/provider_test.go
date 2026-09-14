package commitment

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bperin/trust/chain/broadcast"
	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/rpc"
)

// fakeRPCClient is a scriptable RPCClient fake. Each method returns
// the scripted result/error and records its last call arguments.
type fakeRPCClient struct {
	mu sync.Mutex

	sendRawTxResult string
	sendRawTxErr    error
	lastRawTx       string

	receiptResult interface{}
	receiptErr    error
	lastReceipt   string

	blockNumberResult string
	blockNumberErr    error

	callResult string
	callErr    error
	lastCall   map[string]interface{}
	lastTag    string
}

func (f *fakeRPCClient) ChainID(ctx context.Context) (string, error) {
	return "", nil
}
func (f *fakeRPCClient) GetTransactionCount(ctx context.Context, addr, blockTag string) (string, error) {
	return "", nil
}
func (f *fakeRPCClient) EstimateGas(ctx context.Context, tx map[string]interface{}) (string, error) {
	return "", nil
}
func (f *fakeRPCClient) GasPrice(ctx context.Context) (string, error) { return "", nil }
func (f *fakeRPCClient) MaxPriorityFeePerGas(ctx context.Context) (string, error) {
	return "", nil
}
func (f *fakeRPCClient) FeeHistory(ctx context.Context, bc, nb string, rp []float64) (interface{}, error) {
	return nil, nil
}
func (f *fakeRPCClient) SendRawTransaction(ctx context.Context, rawTx string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastRawTx = rawTx
	return f.sendRawTxResult, f.sendRawTxErr
}
func (f *fakeRPCClient) GetTransactionReceipt(ctx context.Context, txHash string) (interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastReceipt = txHash
	return f.receiptResult, f.receiptErr
}
func (f *fakeRPCClient) GetTransactionByHash(ctx context.Context, txHash string) (interface{}, error) {
	return nil, nil
}
func (f *fakeRPCClient) BlockNumber(ctx context.Context) (string, error) {
	return f.blockNumberResult, f.blockNumberErr
}
func (f *fakeRPCClient) Call(ctx context.Context, call map[string]interface{}, blockTag string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastCall = call
	f.lastTag = blockTag
	return f.callResult, f.callErr
}

// validReceiptJSON returns a receipt map matching broadcast.parseReceipt's
// required fields with the given status and block number.
func validReceiptJSON(status, blockNum string) map[string]interface{} {
	return map[string]interface{}{
		"status":           status,
		"blockHash":        "0xblockhash",
		"blockNumber":      blockNum,
		"transactionHash":  "0xtxhash",
		"transactionIndex": "0x0",
		"gasUsed":          "0x5208",
		"contractAddress":  nil,
		"logs":             []interface{}{},
	}
}

func TestRPCProvider_SendTx(t *testing.T) {
	fake := &fakeRPCClient{sendRawTxResult: "0xtxhash"}
	p := NewRPCProvider(fake)

	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	hash, err := p.SendTx(context.Background(), raw)
	if err != nil {
		t.Fatalf("SendTx err = %v, want nil", err)
	}
	if hash != "0xtxhash" {
		t.Errorf("SendTx hash = %q, want %q", hash, "0xtxhash")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	want := "0x" + hexEncode(raw)
	if fake.lastRawTx != want {
		t.Errorf("recorded raw = %q, want %q", fake.lastRawTx, want)
	}
}

func TestRPCProvider_Receipt(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fake := &fakeRPCClient{receiptResult: validReceiptJSON("0x1", "0x10")}
		p := NewRPCProvider(fake)

		r, err := p.Receipt(context.Background(), "0xhash")
		if err != nil {
			t.Fatalf("Receipt err = %v, want nil", err)
		}
		if r == nil {
			t.Fatal("Receipt = nil, want non-nil")
		}
		if r.Status != 1 {
			t.Errorf("Status = %d, want 1", r.Status)
		}
		if r.BlockNumber != 16 {
			t.Errorf("BlockNumber = %d, want 16", r.BlockNumber)
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if fake.lastReceipt != "0xhash" {
			t.Errorf("recorded hash = %q, want %q", fake.lastReceipt, "0xhash")
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		fake := &fakeRPCClient{receiptResult: nil}
		p := NewRPCProvider(fake)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := p.Receipt(ctx, "0xhash")
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Receipt err = %v, want context.Canceled", err)
		}
	})
}

func TestRPCProvider_BlockNumber(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fake := &fakeRPCClient{blockNumberResult: "0x10"}
		p := NewRPCProvider(fake)

		n, err := p.BlockNumber(context.Background())
		if err != nil {
			t.Fatalf("BlockNumber err = %v, want nil", err)
		}
		if n != 16 {
			t.Errorf("BlockNumber = %d, want 16", n)
		}
	})

	t.Run("overflow", func(t *testing.T) {
		fake := &fakeRPCClient{blockNumberResult: "0x1" + strings.Repeat("0", 16)}
		p := NewRPCProvider(fake)

		_, err := p.BlockNumber(context.Background())
		if !errors.Is(err, rpc.ErrBlockNumberOverflow) {
			t.Errorf("BlockNumber err = %v, want rpc.ErrBlockNumberOverflow", err)
		}
	})
}

func TestRPCProvider_Root(t *testing.T) {
	addr := ethereum.Address{0xde, 0xad, 0xbe, 0xef}

	t.Run("success 32 bytes", func(t *testing.T) {
		var want [32]byte
		for i := range want {
			want[i] = byte(i)
		}
		fake := &fakeRPCClient{callResult: "0x" + hexEncode(want[:])}
		p := NewRPCProvider(fake)

		got, err := p.Root(context.Background(), addr, "0x5")
		if err != nil {
			t.Fatalf("Root err = %v, want nil", err)
		}
		if got != want {
			t.Errorf("Root = %x, want %x", got, want)
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if fake.lastTag != "0x5" {
			t.Errorf("recorded tag = %q, want %q", fake.lastTag, "0x5")
		}
		if fake.lastCall["to"] != addr.Hex() {
			t.Errorf("recorded to = %q, want %q", fake.lastCall["to"], addr.Hex())
		}
		// data must be 0x + 4-byte root() selector
		data, ok := fake.lastCall["data"].(string)
		if !ok {
			t.Fatalf("data is %T, want string", fake.lastCall["data"])
		}
		if len(data) != 10 {
			t.Errorf("data len = %d, want 10 (0x + 4 bytes)", len(data))
		}
	})

	t.Run("wrong length 20 bytes", func(t *testing.T) {
		fake := &fakeRPCClient{callResult: "0x" + strings.Repeat("aa", 20)}
		p := NewRPCProvider(fake)

		_, err := p.Root(context.Background(), addr, "latest")
		if !errors.Is(err, ErrRootGetterFailed) {
			t.Errorf("Root err = %v, want ErrRootGetterFailed", err)
		}
	})

	t.Run("zero bytes", func(t *testing.T) {
		fake := &fakeRPCClient{callResult: "0x"}
		p := NewRPCProvider(fake)

		_, err := p.Root(context.Background(), addr, "latest")
		if !errors.Is(err, ErrRootGetterFailed) {
			t.Errorf("Root err = %v, want ErrRootGetterFailed", err)
		}
	})

	t.Run("33 bytes", func(t *testing.T) {
		fake := &fakeRPCClient{callResult: "0x" + strings.Repeat("aa", 33)}
		p := NewRPCProvider(fake)

		_, err := p.Root(context.Background(), addr, "latest")
		if !errors.Is(err, ErrRootGetterFailed) {
			t.Errorf("Root err = %v, want ErrRootGetterFailed", err)
		}
	})

	t.Run("invalid hex", func(t *testing.T) {
		fake := &fakeRPCClient{callResult: "0xnothex"}
		p := NewRPCProvider(fake)

		_, err := p.Root(context.Background(), addr, "latest")
		if err == nil {
			t.Error("Root err = nil, want non-nil for invalid hex")
		}
	})
}

func TestRPCProvider_NilClient(t *testing.T) {
	p := NewRPCProvider(nil)

	t.Run("SendTx", func(t *testing.T) {
		_, err := p.SendTx(context.Background(), []byte{1})
		if err == nil {
			t.Error("SendTx err = nil, want non-nil")
		}
	})
	t.Run("Receipt", func(t *testing.T) {
		_, err := p.Receipt(context.Background(), "0xhash")
		if err == nil {
			t.Error("Receipt err = nil, want non-nil")
		}
	})
	t.Run("BlockNumber", func(t *testing.T) {
		_, err := p.BlockNumber(context.Background())
		if err == nil {
			t.Error("BlockNumber err = nil, want non-nil")
		}
	})
	t.Run("Root", func(t *testing.T) {
		_, err := p.Root(context.Background(), ethereum.Address{1}, "latest")
		if err == nil {
			t.Error("Root err = nil, want non-nil")
		}
	})
}

func TestWithPollInterval(t *testing.T) {
	t.Run("positive overrides default", func(t *testing.T) {
		p := NewRPCProvider(&fakeRPCClient{}, WithPollInterval(500*time.Millisecond))
		if p.pollInterval != 500*time.Millisecond {
			t.Errorf("pollInterval = %v, want 500ms", p.pollInterval)
		}
	})
	t.Run("zero keeps default", func(t *testing.T) {
		p := NewRPCProvider(&fakeRPCClient{}, WithPollInterval(0))
		if p.pollInterval != broadcast.DefaultPollInterval {
			t.Errorf("pollInterval = %v, want default %v", p.pollInterval, broadcast.DefaultPollInterval)
		}
	})
	t.Run("negative keeps default", func(t *testing.T) {
		p := NewRPCProvider(&fakeRPCClient{}, WithPollInterval(-1*time.Second))
		if p.pollInterval != broadcast.DefaultPollInterval {
			t.Errorf("pollInterval = %v, want default %v", p.pollInterval, broadcast.DefaultPollInterval)
		}
	})
}

func TestRPCProvider_ErrorPropagation(t *testing.T) {
	sentinel := errors.New("rpc: boom")

	t.Run("SendTx", func(t *testing.T) {
		fake := &fakeRPCClient{sendRawTxErr: sentinel}
		p := NewRPCProvider(fake)
		_, err := p.SendTx(context.Background(), []byte{1})
		if !errors.Is(err, sentinel) {
			t.Errorf("SendTx err = %v, want sentinel", err)
		}
	})
	t.Run("BlockNumber", func(t *testing.T) {
		fake := &fakeRPCClient{blockNumberErr: sentinel}
		p := NewRPCProvider(fake)
		_, err := p.BlockNumber(context.Background())
		if !errors.Is(err, sentinel) {
			t.Errorf("BlockNumber err = %v, want sentinel", err)
		}
	})
	t.Run("Root", func(t *testing.T) {
		fake := &fakeRPCClient{callErr: sentinel}
		p := NewRPCProvider(fake)
		_, err := p.Root(context.Background(), ethereum.Address{1}, "latest")
		if !errors.Is(err, sentinel) {
			t.Errorf("Root err = %v, want sentinel", err)
		}
	})
}

// hexEncode is a test-local hex encoder to avoid importing encoding/hex
// just for a one-liner in multiple tests.
func hexEncode(b []byte) string {
	const hexc = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexc[v>>4]
		out[i*2+1] = hexc[v&0x0f]
	}
	return string(out)
}
