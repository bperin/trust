package proof

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bperin/chain/evm"
	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/credential"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/evidence"
	"github.com/bperin/trust/merkle"
)

// ctEqual32 compares two [32]byte values in constant time.
func ctEqual32(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// randBytes returns n random bytes from crypto/rand.
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: got error %v, want nil", err)
	}
	return b
}

// randBatchID returns a random non-zero batch ID.
func randBatchID(t *testing.T) merkle.BatchID {
	t.Helper()
	var id merkle.BatchID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("rand.Read: got error %v, want nil", err)
	}
	return id
}

// Fixed validity window — deterministic across runs.
var (
	winStart = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	winEnd   = winStart.AddDate(1, 0, 0)
)

// buildSignedAttestation creates a valid signed attestation for
// testing. The canonical hash is the Merkle leaf.
func buildSignedAttestation(t *testing.T) attestation.Attestation {
	t.Helper()
	priv, _, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: got error %v, want nil", err)
	}

	claim := &credential.VersionedClaim{
		Version:   1,
		Schema:    "product.attest",
		Subject:   "did:example:subject",
		Resource:  "res-a",
		Issuer:    "did:example:claimer",
		IssuedAt:  winStart,
		NotBefore: winStart,
		NotAfter:  winEnd,
		Payload:   map[string]interface{}{"product": "widget", "qty": float64(42)},
		Evidence: []evidence.EvidenceRef{
			{
				Type:        "pdf",
				URI:         "ipfs://QmEvidenceHash",
				ContentHash: evidence.HashContent([]byte("evidence-bytes")),
			},
		},
	}

	// A non-zero AuthorityRef is required by VerifyAttestation.
	ref := [32]byte{}
	copy(ref[:], randBytes(t, 32))

	att := attestation.Attestation{
		Claim:               claim,
		Issuer:              "did:example:attester",
		SigningKeyID:        "leaf-key-1",
		SigningKeyVersion:   1,
		AuthorityRef:        ref,
		DelegationChainHash: ref,
		Evidence:            claim.Evidence,
		IssuedAt:            winStart,
		NotBefore:           winStart,
		NotAfter:            winEnd,
		Status:              "active",
	}
	if err := attestation.SignAttestation(&att, priv); err != nil {
		t.Fatalf("SignAttestation: got error %v, want nil", err)
	}
	return att
}

// buildChainProof assembles a valid ChainProof from a signed
// attestation. It creates a Merkle batch containing the attestation's
// canonical hash as a leaf, generates an inclusion proof, and returns
// the proof plus the Merkle root and batch ID.
func buildChainProof(t *testing.T, numLeaves int) (ChainProof, merkle.BatchID, [32]byte) {
	t.Helper()

	att := buildSignedAttestation(t)
	canonicalHash, err := attestation.CanonicalHash(&att)
	if err != nil {
		t.Fatalf("CanonicalHash: got error %v, want nil", err)
	}

	// Build a Merkle batch with the canonical hash at a known index.
	leaves := make([][32]byte, numLeaves)
	for i := range leaves {
		if i == 0 {
			leaves[i] = canonicalHash
		} else {
			copy(leaves[i][:], randBytes(t, 32))
		}
	}

	batchID := randBatchID(t)
	batch, err := merkle.NewBatch(batchID, 1, 1, leaves)
	if err != nil {
		t.Fatalf("NewBatch: got error %v, want nil", err)
	}

	merkleProof, err := merkle.InclusionProof(batch, 0)
	if err != nil {
		t.Fatalf("InclusionProof: got error %v, want nil", err)
	}

	contractAddr := [20]byte{}
	copy(contractAddr[:], randBytes(t, 20))
	txHash := [32]byte{}
	copy(txHash[:], randBytes(t, 32))

	proof := ChainProof{
		Attestation:     att,
		CanonicalHash:   canonicalHash,
		LeafIndex:       0,
		MerkleProof:     merkleProof,
		MerkleRoot:      batch.Root,
		ContractAddress: contractAddr,
		TxHash:          txHash,
		BlockMetadata:   BlockMetadata{BlockNumber: 1_000_000, Timestamp: 1700000000},
		BatchID:         batchID,
		Sequence:        1,
		ProtocolVersion: 1,
	}

	return proof, batchID, batch.Root
}

// mockLookup is a test double for the RootLookup interface. It returns
// a canned OnChainRoot or a configured error.
type mockLookup struct {
	root evm.OnChainRoot
	err  error
}

func (m *mockLookup) Lookup(_ context.Context, _ merkle.BatchID) (evm.OnChainRoot, error) {
	if m.err != nil {
		return evm.OnChainRoot{}, m.err
	}
	return m.root, nil
}

// matchingLookup returns a mockLookup whose on-chain root matches the
// proof's MerkleRoot.
func matchingLookup(merkleRoot [32]byte, batchID merkle.BatchID) *mockLookup {
	return &mockLookup{
		root: evm.OnChainRoot{
			BatchID:         batchID,
			MerkleRoot:      merkleRoot,
			Sequence:        1,
			ProtocolVersion: 1,
			BlockNumber:     1_000_000,
		},
	}
}

func TestVerifyChainProofCommitted(t *testing.T) {
	t.Parallel()

	const finalityThreshold = 12

	cases := []struct {
		name         string
		numLeaves    int
		currentBlock uint64
		confirmBlock uint64
		wantStatus   Status
	}{
		{
			name:         "single leaf at threshold",
			numLeaves:    1,
			currentBlock: 1_000_012,
			confirmBlock: 1_000_000,
			wantStatus:   StatusCommitted,
		},
		{
			name:         "single leaf above threshold",
			numLeaves:    1,
			currentBlock: 1_000_100,
			confirmBlock: 1_000_000,
			wantStatus:   StatusCommitted,
		},
		{
			name:         "multi leaf at threshold",
			numLeaves:    4,
			currentBlock: 1_000_012,
			confirmBlock: 1_000_000,
			wantStatus:   StatusCommitted,
		},
		{
			name:         "multi leaf above threshold",
			numLeaves:    8,
			currentBlock: 1_000_999,
			confirmBlock: 1_000_000,
			wantStatus:   StatusCommitted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			proof, batchID, merkleRoot := buildChainProof(t, tc.numLeaves)
			proof.BlockMetadata.BlockNumber = tc.confirmBlock

			opts := VerifyOptions{
				Lookup:            matchingLookup(merkleRoot, batchID),
				CurrentBlock:      tc.currentBlock,
				FinalityThreshold: finalityThreshold,
			}

			status, err := VerifyChainProof(proof, opts)
			if err != nil {
				t.Fatalf("VerifyChainProof: got error %v, want nil", err)
			}
			if status != tc.wantStatus {
				t.Errorf("status: got %s, want %s", status, tc.wantStatus)
			}
		})
	}
}

func TestVerifyChainProofPending(t *testing.T) {
	t.Parallel()

	const finalityThreshold = 12

	cases := []struct {
		name         string
		currentBlock uint64
		confirmBlock uint64
		wantStatus   Status
	}{
		{
			name:         "below threshold by one",
			currentBlock: 1_000_011,
			confirmBlock: 1_000_000,
			wantStatus:   StatusPending,
		},
		{
			name:         "below threshold by many",
			currentBlock: 1_000_001,
			confirmBlock: 1_000_000,
			wantStatus:   StatusPending,
		},
		{
			name:         "same block as confirmation",
			currentBlock: 1_000_000,
			confirmBlock: 1_000_000,
			wantStatus:   StatusPending,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			proof, batchID, merkleRoot := buildChainProof(t, 3)
			proof.BlockMetadata.BlockNumber = tc.confirmBlock

			opts := VerifyOptions{
				Lookup:            matchingLookup(merkleRoot, batchID),
				CurrentBlock:      tc.currentBlock,
				FinalityThreshold: finalityThreshold,
			}

			status, err := VerifyChainProof(proof, opts)
			if err != nil {
				t.Fatalf("VerifyChainProof: got error %v, want nil", err)
			}
			if status != tc.wantStatus {
				t.Errorf("status: got %s, want %s", status, tc.wantStatus)
			}
		})
	}
}

func TestVerifyChainProofRootMismatch(t *testing.T) {
	t.Parallel()

	proof, batchID, _ := buildChainProof(t, 3)

	// On-chain root differs from the proof's MerkleRoot.
	wrongRoot := [32]byte{}
	copy(wrongRoot[:], randBytes(t, 32))
	mismatchLookup := &mockLookup{
		root: evm.OnChainRoot{
			BatchID:    batchID,
			MerkleRoot: wrongRoot,
		},
	}

	opts := VerifyOptions{
		Lookup:            mismatchLookup,
		CurrentBlock:      1_000_100,
		FinalityThreshold: 12,
	}

	_, err := VerifyChainProof(proof, opts)
	if !errors.Is(err, ErrRootMismatch) {
		t.Errorf("VerifyChainProof with mismatched root: got error %v, want errors.Is(_, ErrRootMismatch)", err)
	}
}

func TestVerifyChainProofRPCError(t *testing.T) {
	t.Parallel()

	proof, _, _ := buildChainProof(t, 3)

	rpcErr := &mockLookup{err: evm.ErrRPCError}

	opts := VerifyOptions{
		Lookup:            rpcErr,
		CurrentBlock:      1_000_100,
		FinalityThreshold: 12,
	}

	_, err := VerifyChainProof(proof, opts)
	if !errors.Is(err, evm.ErrRPCError) {
		t.Errorf("VerifyChainProof on RPC error: got error %v, want errors.Is(_, evm.ErrRPCError)", err)
	}
}

func TestVerifyChainProofRootNotFound(t *testing.T) {
	t.Parallel()

	proof, _, _ := buildChainProof(t, 3)

	notFoundLookup := &mockLookup{err: evm.ErrRootNotFound}

	opts := VerifyOptions{
		Lookup:            notFoundLookup,
		CurrentBlock:      1_000_100,
		FinalityThreshold: 12,
	}

	_, err := VerifyChainProof(proof, opts)
	if !errors.Is(err, evm.ErrRootNotFound) {
		t.Errorf("VerifyChainProof on root not found: got error %v, want errors.Is(_, evm.ErrRootNotFound)", err)
	}
}

func TestVerifyChainProofInvalidMerkleProof(t *testing.T) {
	t.Parallel()

	proof, batchID, merkleRoot := buildChainProof(t, 4)

	// Tamper with the Merkle proof: flip a byte in the first element.
	if len(proof.MerkleProof) == 0 {
		t.Fatalf("MerkleProof is empty, need at least one element")
	}
	tampered := make([][]byte, len(proof.MerkleProof))
	copy(tampered, proof.MerkleProof)
	tampered[0] = make([]byte, len(proof.MerkleProof[0]))
	copy(tampered[0], proof.MerkleProof[0])
	tampered[0][1] ^= 0xff // flip a byte in the sibling hash
	proof.MerkleProof = tampered

	opts := VerifyOptions{
		Lookup:            matchingLookup(merkleRoot, batchID),
		CurrentBlock:      1_000_100,
		FinalityThreshold: 12,
	}

	_, err := VerifyChainProof(proof, opts)
	if err == nil {
		t.Errorf("VerifyChainProof with tampered Merkle proof: got nil error, want non-nil")
	}
	if !errors.Is(err, merkle.ErrTamperedLeaf) {
		t.Errorf("VerifyChainProof with tampered Merkle proof: got error %v, want errors.Is(_, merkle.ErrTamperedLeaf)", err)
	}
}

func TestVerifyChainProofCanonicalHashMismatch(t *testing.T) {
	t.Parallel()

	proof, batchID, merkleRoot := buildChainProof(t, 3)

	// Tamper with the canonical hash field — it no longer matches
	// the attestation's recomputed canonical hash.
	proof.CanonicalHash[0] ^= 0xff

	opts := VerifyOptions{
		Lookup:            matchingLookup(merkleRoot, batchID),
		CurrentBlock:      1_000_100,
		FinalityThreshold: 12,
	}

	_, err := VerifyChainProof(proof, opts)
	if !errors.Is(err, ErrCanonicalHashMismatch) {
		t.Errorf("VerifyChainProof with mismatched canonical hash: got error %v, want errors.Is(_, ErrCanonicalHashMismatch)", err)
	}
}

func TestVerifyChainProofWrongMerkleRoot(t *testing.T) {
	t.Parallel()

	proof, batchID, _ := buildChainProof(t, 3)

	// Replace the proof's MerkleRoot with a wrong value. The inclusion
	// proof was generated for the original root, so it will fail.
	wrongRoot := [32]byte{}
	copy(wrongRoot[:], randBytes(t, 32))
	proof.MerkleRoot = wrongRoot

	// The on-chain root matches the wrong root (to isolate the
	// inclusion proof failure).
	mismatchLookup := &mockLookup{
		root: evm.OnChainRoot{
			BatchID:    batchID,
			MerkleRoot: wrongRoot,
		},
	}

	opts := VerifyOptions{
		Lookup:            mismatchLookup,
		CurrentBlock:      1_000_100,
		FinalityThreshold: 12,
	}

	_, err := VerifyChainProof(proof, opts)
	if err == nil {
		t.Errorf("VerifyChainProof with wrong MerkleRoot: got nil error, want non-nil")
	}
	// The inclusion proof should fail since the leaf+proof don't
	// commit to the wrong root.
	if !errors.Is(err, merkle.ErrTamperedLeaf) {
		t.Errorf("VerifyChainProof with wrong MerkleRoot: got error %v, want errors.Is(_, merkle.ErrTamperedLeaf)", err)
	}
}

func TestVerifyChainProofCurrentBlockBelowConfirmation(t *testing.T) {
	t.Parallel()

	proof, batchID, merkleRoot := buildChainProof(t, 3)
	proof.BlockMetadata.BlockNumber = 1_000_000

	// Current block is before the confirmation block — defensive error.
	opts := VerifyOptions{
		Lookup:            matchingLookup(merkleRoot, batchID),
		CurrentBlock:      999_999,
		FinalityThreshold: 12,
	}

	status, err := VerifyChainProof(proof, opts)
	if !errors.Is(err, ErrBelowFinalityThreshold) {
		t.Errorf("VerifyChainProof with current block below confirmation: got error %v, want errors.Is(_, ErrBelowFinalityThreshold)", err)
	}
	if status != StatusPending {
		t.Errorf("status: got %s, want %s", status, StatusPending)
	}
}

// TestStatusString verifies the String method covers all statuses.
func TestStatusString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		status Status
		want   string
	}{
		{StatusPending, "pending"},
		{StatusCommitted, "committed"},
		{Status(99), "unknown(99)"},
	}

	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			got := tc.status.String()
			if got != tc.want {
				t.Errorf("String(): got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestChainProofAssembly verifies that a chain proof carries all
// required fields and they are consistent with the attestation and
// Merkle batch.
func TestChainProofAssembly(t *testing.T) {
	t.Parallel()

	proof, batchID, merkleRoot := buildChainProof(t, 5)

	// Verify the proof carries all required fields.
	if !ctEqual32(proof.MerkleRoot, merkleRoot) {
		t.Errorf("MerkleRoot: got %x, want %x", proof.MerkleRoot, merkleRoot)
	}
	if !ctEqual32(proof.BatchID, batchID) {
		t.Errorf("BatchID: got %x, want %x", proof.BatchID, batchID)
	}

	// The canonical hash must match the attestation's.
	computed, err := attestation.CanonicalHash(&proof.Attestation)
	if err != nil {
		t.Fatalf("CanonicalHash: got error %v, want nil", err)
	}
	if !ctEqual32(proof.CanonicalHash, computed) {
		t.Errorf("CanonicalHash: got %x, want %x", proof.CanonicalHash, computed)
	}

	// The Merkle inclusion proof must verify against the root.
	if err := merkle.VerifyInclusion(proof.MerkleRoot, proof.LeafIndex, proof.CanonicalHash, proof.MerkleProof); err != nil {
		t.Errorf("VerifyInclusion: got error %v, want nil", err)
	}

	// The contract address and tx hash must be non-zero.
	var zero20 [20]byte
	if subtle.ConstantTimeCompare(proof.ContractAddress[:], zero20[:]) == 1 {
		t.Errorf("ContractAddress is zero")
	}
	var zero32 [32]byte
	if subtle.ConstantTimeCompare(proof.TxHash[:], zero32[:]) == 1 {
		t.Errorf("TxHash is zero")
	}

	// Sequence and protocol version must be set.
	if proof.Sequence != 1 {
		t.Errorf("Sequence: got %d, want 1", proof.Sequence)
	}
	if proof.ProtocolVersion != 1 {
		t.Errorf("ProtocolVersion: got %d, want 1", proof.ProtocolVersion)
	}
}

// TestNoCrossModuleImports verifies that the proof package does not
// import the forbidden module. This enforces the cross-module
// isolation rule: chain may import trust but never the forbidden
// identity/session module.
func TestNoCrossModuleImports(t *testing.T) {
	t.Parallel()

	// Parse every .go file in this package (excluding _test.go) and
	// fail if any import path contains the forbidden module name.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parser.ParseDir: %v", err)
	}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if strings.Contains(path, "auth") {
					t.Errorf("forbidden import in %s: %s", filepath.Base(fset.Position(imp.Pos()).Filename), path)
				}
			}
		}
	}
}

// Ensure the ast/parser/token imports are used.
var _ = ast.ImportSpec{}
var _ = token.NewFileSet
