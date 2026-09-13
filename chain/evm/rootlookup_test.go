package evm

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"testing"

	"github.com/bperin/trust/trust/merkle"
)

// mockRPC is a test double for RPCClient. It returns canned results
// keyed by batch ID, or a configured error. No live network.
type mockRPC struct {
	// roots maps batch ID to raw ABI-encoded result.
	roots map[[32]byte][]byte
	// err is returned by GetRoot when non-nil (transport failure).
	err error
	// blockNum is returned by BlockNumber.
	blockNum uint64
	// blockErr is returned by BlockNumber when non-nil.
	blockErr error
	// lastContract is the contract address passed to the last GetRoot call.
	lastContract [20]byte
	// lastBatchID is the batch ID passed to the last GetRoot call.
	lastBatchID [32]byte
}

func (m *mockRPC) GetRoot(_ context.Context, contractAddress [20]byte, batchID [32]byte) ([]byte, error) {
	m.lastContract = contractAddress
	m.lastBatchID = batchID
	if m.err != nil {
		return nil, m.err
	}
	if raw, ok := m.roots[batchID]; ok {
		return raw, nil
	}
	// Batch not on chain: empty result signals not found.
	return nil, nil
}

func (m *mockRPC) BlockNumber(_ context.Context) (uint64, error) {
	if m.blockErr != nil {
		return 0, m.blockErr
	}
	return m.blockNum, nil
}

// encodeRoot encodes an OnChainRoot's return fields into the raw
// ABI encoding that decodeRoot expects: 5 × 32-byte words.
func encodeRoot(root OnChainRoot) []byte {
	raw := make([]byte, abiResultLen)
	copy(raw[0:32], root.MerkleRoot[:])
	encodeUint64(raw[32:64], root.Sequence)
	encodeUint64(raw[64:96], uint64(root.ProtocolVersion))
	encodeUint64(raw[96:128], root.BlockNumber)
	copy(raw[128:160], root.TxHash[:])
	return raw
}

// encodeUint64 writes v as a 32-byte big-endian uint256 word,
// left-padded with zeros (ABI encoding).
func encodeUint64(word []byte, v uint64) {
	for i := 0; i < 8; i++ {
		word[31-i] = byte(v >> (8 * i))
	}
}

// randBatchID returns a random non-zero batch ID for testing.
func randBatchID(t *testing.T) merkle.BatchID {
	t.Helper()
	var id merkle.BatchID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("rand.Read: got error %v, want nil", err)
	}
	return id
}

// randBytes returns n random bytes.
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: got error %v, want nil", err)
	}
	return b
}

// ctEqual32 compares two [32]byte values in constant time.
func ctEqual32(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func TestLookupRoundTrip(t *testing.T) {
	t.Parallel()

	contractAddr := [20]byte{}
	copy(contractAddr[:], randBytes(t, 20))

	batchID := randBatchID(t)
	merkleRoot := [32]byte{}
	copy(merkleRoot[:], randBytes(t, 32))
	txHash := [32]byte{}
	copy(txHash[:], randBytes(t, 32))

	want := OnChainRoot{
		BatchID:         batchID,
		MerkleRoot:      merkleRoot,
		Sequence:        42,
		ProtocolVersion: 3,
		BlockNumber:     1_000_000,
		TxHash:          txHash,
	}

	mock := &mockRPC{
		roots:    map[[32]byte][]byte{batchID: encodeRoot(want)},
		blockNum: 1_001_000,
	}

	rl := RootLookup{
		ContractAddress:   contractAddr,
		Client:            mock,
		FinalityThreshold: 12,
	}

	got, err := rl.Lookup(context.Background(), batchID)
	if err != nil {
		t.Fatalf("Lookup: got error %v, want nil", err)
	}

	// Verify the contract address and batch ID were passed through.
	if mock.lastContract != contractAddr {
		t.Errorf("contract address: got %x, want %x", mock.lastContract, contractAddr)
	}
	if mock.lastBatchID != batchID {
		t.Errorf("batch ID: got %x, want %x", mock.lastBatchID, batchID)
	}

	// Constant-time comparison for all hash fields.
	if !ctEqual32(got.MerkleRoot, want.MerkleRoot) {
		t.Errorf("merkleRoot: got %x, want %x", got.MerkleRoot, want.MerkleRoot)
	}
	if !ctEqual32(got.TxHash, want.TxHash) {
		t.Errorf("txHash: got %x, want %x", got.TxHash, want.TxHash)
	}
	if !ctEqual32(got.BatchID, want.BatchID) {
		t.Errorf("batchID: got %x, want %x", got.BatchID, want.BatchID)
	}
	if got.Sequence != want.Sequence {
		t.Errorf("sequence: got %d, want %d", got.Sequence, want.Sequence)
	}
	if got.ProtocolVersion != want.ProtocolVersion {
		t.Errorf("protocolVersion: got %d, want %d", got.ProtocolVersion, want.ProtocolVersion)
	}
	if got.BlockNumber != want.BlockNumber {
		t.Errorf("blockNumber: got %d, want %d", got.BlockNumber, want.BlockNumber)
	}
}

func TestLookupRootNotFound(t *testing.T) {
	t.Parallel()

	contractAddr := [20]byte{}
	copy(contractAddr[:], randBytes(t, 20))

	// The mock has no roots — every batch ID is absent.
	mock := &mockRPC{
		roots: map[[32]byte][]byte{},
	}

	rl := RootLookup{
		ContractAddress:   contractAddr,
		Client:            mock,
		FinalityThreshold: 12,
	}

	batchID := randBatchID(t)

	_, err := rl.Lookup(context.Background(), batchID)
	if !errors.Is(err, ErrRootNotFound) {
		t.Errorf("Lookup for absent batch: got error %v, want errors.Is(_, ErrRootNotFound)", err)
	}
}

func TestLookupRPCError(t *testing.T) {
	t.Parallel()

	contractAddr := [20]byte{}
	copy(contractAddr[:], randBytes(t, 20))

	transportErr := errors.New("connection refused")
	mock := &mockRPC{
		err: transportErr,
	}

	rl := RootLookup{
		ContractAddress:   contractAddr,
		Client:            mock,
		FinalityThreshold: 12,
	}

	batchID := randBatchID(t)

	_, err := rl.Lookup(context.Background(), batchID)
	if !errors.Is(err, ErrRPCError) {
		t.Errorf("Lookup on transport failure: got error %v, want errors.Is(_, ErrRPCError)", err)
	}
	// The original error should be wrapped in the message.
	if !errors.Is(err, transportErr) {
		t.Errorf("Lookup on transport failure: got error %v, want wrapped transport error", err)
	}
}

func TestCurrentBlock(t *testing.T) {
	t.Parallel()

	mock := &mockRPC{blockNum: 9_999_999}
	rl := RootLookup{
		Client:            mock,
		FinalityThreshold: 12,
	}

	got, err := rl.CurrentBlock(context.Background())
	if err != nil {
		t.Fatalf("CurrentBlock: got error %v, want nil", err)
	}
	if got != 9_999_999 {
		t.Errorf("CurrentBlock: got %d, want %d", got, 9_999_999)
	}
}

func TestCurrentBlockRPCError(t *testing.T) {
	t.Parallel()

	mock := &mockRPC{blockErr: errors.New("timeout")}
	rl := RootLookup{
		Client:            mock,
		FinalityThreshold: 12,
	}

	_, err := rl.CurrentBlock(context.Background())
	if !errors.Is(err, ErrRPCError) {
		t.Errorf("CurrentBlock on failure: got error %v, want errors.Is(_, ErrRPCError)", err)
	}
}

// TestDecodeRootRoundTrip verifies that encodeRoot and decodeRoot are
// inverses for a range of values, including zero and max uint64.
func TestDecodeRootRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		sequence uint64
		proto    uint64
		block    uint64
	}{
		{"zeros", 0, 0, 0},
		{"max uint64", ^uint64(0), ^uint64(0), ^uint64(0)},
		{"typical", 42, 3, 1_000_000},
		{"small", 1, 1, 1},
	}

	batchID := randBatchID(t)
	merkleRoot := [32]byte{}
	copy(merkleRoot[:], randBytes(t, 32))
	txHash := [32]byte{}
	copy(txHash[:], randBytes(t, 32))

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want := OnChainRoot{
				BatchID:         batchID,
				MerkleRoot:      merkleRoot,
				Sequence:        tc.sequence,
				ProtocolVersion: uint(tc.proto),
				BlockNumber:     tc.block,
				TxHash:          txHash,
			}
			raw := encodeRoot(want)
			got, err := decodeRoot(raw, batchID)
			if err != nil {
				t.Fatalf("decodeRoot: got error %v, want nil", err)
			}
			if !ctEqual32(got.MerkleRoot, want.MerkleRoot) {
				t.Errorf("merkleRoot: got %x, want %x", got.MerkleRoot, want.MerkleRoot)
			}
			if got.Sequence != want.Sequence {
				t.Errorf("sequence: got %d, want %d", got.Sequence, want.Sequence)
			}
			if got.ProtocolVersion != want.ProtocolVersion {
				t.Errorf("protocolVersion: got %d, want %d", got.ProtocolVersion, want.ProtocolVersion)
			}
			if got.BlockNumber != want.BlockNumber {
				t.Errorf("blockNumber: got %d, want %d", got.BlockNumber, want.BlockNumber)
			}
			if !ctEqual32(got.TxHash, want.TxHash) {
				t.Errorf("txHash: got %x, want %x", got.TxHash, want.TxHash)
			}
		})
	}
}

func TestDecodeRootShortResult(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one byte", []byte{0x01}},
		{"31 bytes", make([]byte, 31)},
		{"159 bytes", make([]byte, 159)},
	}

	batchID := randBatchID(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := decodeRoot(tc.raw, batchID)
			if err == nil {
				t.Errorf("decodeRoot with %s: got nil error, want non-nil", tc.name)
			}
		})
	}
}

// TestGetRootSelector verifies the selector is the first 4 bytes of
// keccak256("getRoot(bytes32)"). The known value is 0x84f94221.
func TestGetRootSelector(t *testing.T) {
	t.Parallel()

	// keccak256("getRoot(bytes32)") = 0x84f94221...
	// Computed independently to cross-reference.
	want := [4]byte{0x84, 0xf9, 0x42, 0x21}
	if subtle.ConstantTimeCompare(getRootSelector[:], want[:]) != 1 {
		t.Errorf("getRoot selector: got %x, want %x", getRootSelector, want)
	}
}

// TestLookupPassesContractAddress verifies the caller-supplied contract
// address is forwarded to the RPC client, not hardcoded.
func TestLookupPassesContractAddress(t *testing.T) {
	t.Parallel()

	contractAddr := [20]byte{0xde, 0xad, 0xbe, 0xef}
	batchID := randBatchID(t)
	want := OnChainRoot{
		BatchID:    batchID,
		MerkleRoot: [32]byte{0x01},
	}
	mock := &mockRPC{
		roots: map[[32]byte][]byte{batchID: encodeRoot(want)},
	}

	rl := RootLookup{
		ContractAddress:   contractAddr,
		Client:            mock,
		FinalityThreshold: 12,
	}

	if _, err := rl.Lookup(context.Background(), batchID); err != nil {
		t.Fatalf("Lookup: got error %v, want nil", err)
	}
	if mock.lastContract != contractAddr {
		t.Errorf("contract address forwarded: got %x, want %x", mock.lastContract, contractAddr)
	}
}

// TestLookupMultipleBatches verifies the lookup works across multiple
// batch IDs in the same registry.
func TestLookupMultipleBatches(t *testing.T) {
	t.Parallel()

	contractAddr := [20]byte{}
	copy(contractAddr[:], randBytes(t, 20))

	ids := make([]merkle.BatchID, 5)
	roots := make(map[[32]byte][]byte)
	for i := range ids {
		ids[i] = randBatchID(t)
		root := OnChainRoot{
			BatchID:    ids[i],
			MerkleRoot: [32]byte{byte(i + 1)},
			Sequence:   uint64(i),
		}
		roots[ids[i]] = encodeRoot(root)
	}

	mock := &mockRPC{roots: roots}
	rl := RootLookup{
		ContractAddress:   contractAddr,
		Client:            mock,
		FinalityThreshold: 12,
	}

	for i, id := range ids {
		got, err := rl.Lookup(context.Background(), id)
		if err != nil {
			t.Fatalf("Lookup batch %d: got error %v, want nil", i, err)
		}
		wantRoot := [32]byte{byte(i + 1)}
		if !ctEqual32(got.MerkleRoot, wantRoot) {
			t.Errorf("batch %d merkleRoot: got %x, want %x", i, got.MerkleRoot, wantRoot)
		}
		if got.Sequence != uint64(i) {
			t.Errorf("batch %d sequence: got %d, want %d", i, got.Sequence, i)
		}
	}
}
