package commitment

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/bperin/trust/chain/abi"
	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/rlp"
)

// fakeProvider is a scriptable Provider for publish tests.
type fakeProvider struct {
	sendTxResult string
	sendTxErr    error
	lastRawTx    []byte

	receiptResult *Receipt
	receiptErr    error
}

func (f *fakeProvider) SendTx(ctx context.Context, rawTx []byte) (string, error) {
	f.lastRawTx = make([]byte, len(rawTx))
	copy(f.lastRawTx, rawTx)
	return f.sendTxResult, f.sendTxErr
}
func (f *fakeProvider) Receipt(ctx context.Context, txHash string) (*Receipt, error) {
	return f.receiptResult, f.receiptErr
}
func (f *fakeProvider) BlockNumber(ctx context.Context) (uint64, error) { return 0, nil }
func (f *fakeProvider) Root(ctx context.Context, contract ethereum.Address, blockTag string) ([32]byte, error) {
	return [32]byte{}, nil
}

func TestPublishCallData(t *testing.T) {
	root := [32]byte{0x01, 0x02, 0x03}
	data, err := publishCallData(root)
	if err != nil {
		t.Fatalf("publishCallData: %v", err)
	}
	if len(data) != 36 {
		t.Fatalf("data len = %d, want 36 (4 selector + 32 root)", len(data))
	}
	// Selector must be keccak256("publishRoot(bytes32)")[:4].
	sel := abi.FunctionSelector(PublishSignature)
	if !bytes.Equal(data[:4], sel[:]) {
		t.Errorf("selector = %x, want %x", data[:4], sel)
	}
	// Body must be the 32-byte root right-aligned in the ABI word.
	if !bytes.Equal(data[4:], root[:]) {
		t.Errorf("body = %x, want %x", data[4:], root)
	}
}

func TestPublish_Success(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}

	receipt := &Receipt{
		Status:           1,
		BlockHash:        "0xblockhash",
		BlockNumber:      10,
		TransactionHash:  "0x" + repeat("a", 64),
		TransactionIndex: 0,
		GasUsed:          21000,
		ContractAddress:  "",
		Logs:             []interface{}{},
	}
	fp := &fakeProvider{sendTxResult: "0xtxhash", receiptResult: receipt}

	r, err := Publish(context.Background(), a, root, w, fp,
		WithNonce(7), WithGasLimit(21000), WithGasPrice(big.NewInt(1e9)),
	)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if r.Status != 1 {
		t.Errorf("Status = %d, want 1", r.Status)
	}

	// Decode the recorded raw tx and verify fields.
	decoded, err := rlp.Decode(fp.lastRawTx)
	if err != nil {
		t.Fatalf("rlp.Decode: %v", err)
	}
	items, ok := decoded.([]interface{})
	if !ok {
		t.Fatalf("decoded = %T, want []interface{}", decoded)
	}
	if len(items) != 9 {
		t.Fatalf("items = %d, want 9 (nonce, gasPrice, gasLimit, to, value, data, v, r, s)", len(items))
	}

	// nonce (item 0) — 7
	nonce := bytesToUint64(items[0].([]byte))
	if nonce != 7 {
		t.Errorf("nonce = %d, want 7", nonce)
	}

	// gasPrice (item 1) — 1e9 = 0x3b9aca00
	gasPrice := new(big.Int).SetBytes(items[1].([]byte))
	if gasPrice.Cmp(big.NewInt(1e9)) != 0 {
		t.Errorf("gasPrice = %s, want 1e9", gasPrice)
	}

	// gasLimit (item 2) — 21000
	gasLimit := bytesToUint64(items[2].([]byte))
	if gasLimit != 21000 {
		t.Errorf("gasLimit = %d, want 21000", gasLimit)
	}

	// to (item 3) — a.Contract
	to := items[3].([]byte)
	if !bytes.Equal(to, a.Contract[:]) {
		t.Errorf("to = %x, want %x", to, a.Contract)
	}

	// value (item 4) — 0 (empty bytes)
	value := items[4].([]byte)
	if len(value) != 0 {
		t.Errorf("value = %x, want empty (0)", value)
	}

	// data (item 5) — publishCallData(root)
	expectedData, _ := publishCallData(root)
	data := items[5].([]byte)
	if !bytes.Equal(data, expectedData) {
		t.Errorf("data = %x, want %x", data, expectedData)
	}
}

func TestPublish_OptionsApplied(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}

	receipt := &Receipt{Status: 1, TransactionHash: "0x" + repeat("a", 64)}
	fp := &fakeProvider{sendTxResult: "0xhash", receiptResult: receipt}

	_, err := Publish(context.Background(), a, root, w, fp,
		WithNonce(42), WithGasLimit(1), WithGasPrice(big.NewInt(777)),
	)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	decoded, _ := rlp.Decode(fp.lastRawTx)
	items := decoded.([]interface{})

	nonce := bytesToUint64(items[0].([]byte))
	if nonce != 42 {
		t.Errorf("nonce = %d, want 42", nonce)
	}
	gasLimit := bytesToUint64(items[2].([]byte))
	if gasLimit != 1 {
		t.Errorf("gasLimit = %d, want 1", gasLimit)
	}
	gasPrice := new(big.Int).SetBytes(items[1].([]byte))
	if gasPrice.Cmp(big.NewInt(777)) != 0 {
		t.Errorf("gasPrice = %s, want 777", gasPrice)
	}
}

func TestPublish_NilArgs(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	fp := &fakeProvider{}

	t.Run("nil anchor", func(t *testing.T) {
		_, err := Publish(context.Background(), nil, root, w, fp, WithGasLimit(1), WithGasPrice(big.NewInt(1)))
		if !errors.Is(err, ErrNilAnchor) {
			t.Errorf("err = %v, want ErrNilAnchor", err)
		}
	})
	t.Run("nil wallet", func(t *testing.T) {
		_, err := Publish(context.Background(), a, root, nil, fp, WithGasLimit(1), WithGasPrice(big.NewInt(1)))
		if !errors.Is(err, ErrNilWallet) {
			t.Errorf("err = %v, want ErrNilWallet", err)
		}
	})
	t.Run("nil provider", func(t *testing.T) {
		_, err := Publish(context.Background(), a, root, w, nil, WithGasLimit(1), WithGasPrice(big.NewInt(1)))
		if err == nil {
			t.Error("err = nil, want non-nil for nil provider")
		}
	})
}

func TestPublish_MissingTxParams(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	fp := &fakeProvider{}

	t.Run("missing gas limit", func(t *testing.T) {
		_, err := Publish(context.Background(), a, root, w, fp, WithGasPrice(big.NewInt(1)))
		if !errors.Is(err, ErrMissingTxParams) {
			t.Errorf("err = %v, want ErrMissingTxParams", err)
		}
	})
	t.Run("zero gas limit ignored", func(t *testing.T) {
		_, err := Publish(context.Background(), a, root, w, fp, WithGasLimit(0), WithGasPrice(big.NewInt(1)))
		if !errors.Is(err, ErrMissingTxParams) {
			t.Errorf("err = %v, want ErrMissingTxParams", err)
		}
	})
	t.Run("missing gas price", func(t *testing.T) {
		_, err := Publish(context.Background(), a, root, w, fp, WithGasLimit(1))
		if !errors.Is(err, ErrMissingTxParams) {
			t.Errorf("err = %v, want ErrMissingTxParams", err)
		}
	})
	t.Run("nil gas price ignored", func(t *testing.T) {
		_, err := Publish(context.Background(), a, root, w, fp, WithGasLimit(1), WithGasPrice(nil))
		if !errors.Is(err, ErrMissingTxParams) {
			t.Errorf("err = %v, want ErrMissingTxParams", err)
		}
	})
}

func TestPublish_NotConfirmed(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}

	t.Run("status 0", func(t *testing.T) {
		fp := &fakeProvider{
			sendTxResult:  "0xhash",
			receiptResult: &Receipt{Status: 0, TransactionHash: "0x" + repeat("a", 64)},
		}
		_, err := Publish(context.Background(), a, root, w, fp, WithGasLimit(1), WithGasPrice(big.NewInt(1)))
		if !errors.Is(err, ErrNotConfirmed) {
			t.Errorf("err = %v, want ErrNotConfirmed", err)
		}
	})
	t.Run("nil receipt", func(t *testing.T) {
		fp := &fakeProvider{
			sendTxResult:  "0xhash",
			receiptResult: nil,
		}
		_, err := Publish(context.Background(), a, root, w, fp, WithGasLimit(1), WithGasPrice(big.NewInt(1)))
		if !errors.Is(err, ErrNotConfirmed) {
			t.Errorf("err = %v, want ErrNotConfirmed", err)
		}
	})
}

func TestPublish_SendTxError(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	sentinel := errors.New("rpc: send failed")
	fp := &fakeProvider{sendTxErr: sentinel}

	_, err := Publish(context.Background(), a, root, w, fp, WithGasLimit(1), WithGasPrice(big.NewInt(1)))
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
}

func TestPublish_CancelledContext(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	fp := &fakeProvider{
		sendTxErr: context.Canceled,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Publish(ctx, a, root, w, fp, WithGasLimit(1), WithGasPrice(big.NewInt(1)))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestPublish_NonceZeroValid(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	receipt := &Receipt{Status: 1, TransactionHash: "0x" + repeat("a", 64)}
	fp := &fakeProvider{sendTxResult: "0xhash", receiptResult: receipt}

	// Default nonce is 0, which is valid.
	_, err := Publish(context.Background(), a, root, w, fp, WithGasLimit(1), WithGasPrice(big.NewInt(1)))
	if err != nil {
		t.Fatalf("Publish with nonce 0: %v", err)
	}

	decoded, _ := rlp.Decode(fp.lastRawTx)
	items := decoded.([]interface{})
	nonce := items[0].([]byte)
	if len(nonce) != 0 {
		t.Errorf("nonce = %x, want empty (0)", nonce)
	}
}

// bytesToUint64 decodes a minimal big-endian byte slice to uint64.
func bytesToUint64(b []byte) uint64 {
	var n uint64
	for _, v := range b {
		n = (n << 8) | uint64(v)
	}
	return n
}

// repeat returns n copies of character c as a string.
func repeat(c string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = c[0]
	}
	return string(out)
}
