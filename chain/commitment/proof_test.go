package commitment

import (
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/bperin/trust/chain/abi"
	"github.com/bperin/trust/chain/eip712"
	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/wallet"
	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/crypto/secp256k1"
)

// hardhatKey is the well-known Hardhat test account 0 private key.
const hardhatKeyHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

func mustWallet(t *testing.T) *wallet.Wallet {
	t.Helper()
	privBytes, err := hex.DecodeString(hardhatKeyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	priv, err := secp256k1.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	return wallet.NewWallet(priv)
}

func mustAnchor(t *testing.T, chainID int64, addrHex string) *Anchor {
	t.Helper()
	addr, err := ethereum.ParseAddress(addrHex)
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	a, err := NewAnchor(big.NewInt(chainID), addr)
	if err != nil {
		t.Fatalf("NewAnchor: %v", err)
	}
	return a
}

func mustReceipt(txHashHex string, blockNum uint64) Receipt {
	return Receipt{
		Status:           1,
		BlockHash:        "0xblockhash",
		BlockNumber:      blockNum,
		TransactionHash:  txHashHex,
		TransactionIndex: 0,
		GasUsed:          21000,
		ContractAddress:  "",
		Logs:             []interface{}{},
	}
}

func TestProof_RoundTrip(t *testing.T) {
	w := mustWallet(t)
	walletAddr, _ := w.Address()
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x01, 0x02, 0x03}
	r := mustReceipt("0x"+strings.Repeat("aa", 32), 42)

	p, err := Proof(root, a, r, w)
	if err != nil {
		t.Fatalf("Proof err = %v, want nil", err)
	}
	if len(p.Signature) != 65 {
		t.Errorf("Signature len = %d, want 65", len(p.Signature))
	}

	recovered, err := VerifyCommitmentProof(p)
	if err != nil {
		t.Fatalf("VerifyCommitmentProof err = %v, want nil", err)
	}
	if recovered != walletAddr {
		t.Errorf("recovered = %x, want %x", recovered, walletAddr)
	}
}

func TestCommitmentDomain(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")

	domain, domainHash, err := commitmentDomain(a)
	if err != nil {
		t.Fatalf("commitmentDomain err = %v", err)
	}
	if domain.Name != "TrustCommitment" {
		t.Errorf("Name = %q, want %q", domain.Name, "TrustCommitment")
	}
	if domain.Version != "1" {
		t.Errorf("Version = %q, want %q", domain.Version, "1")
	}
	if domain.ChainID.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("ChainID = %v, want 1", domain.ChainID)
	}
	if domain.VerifyingContract != a.Contract {
		t.Errorf("VerifyingContract = %x, want %x", domain.VerifyingContract, a.Contract)
	}

	// Independent recomputation.
	expected, err := eip712.DomainSeparator{
		Name:              "TrustCommitment",
		Version:           "1",
		ChainID:           big.NewInt(1),
		VerifyingContract: a.Contract,
		Salt:              [32]byte{},
	}.Hash()
	if err != nil {
		t.Fatalf("independent domain hash: %v", err)
	}
	if domainHash != expected {
		t.Errorf("domainHash = %x, want %x", domainHash, expected)
	}
}

func TestCommitmentStructHash(t *testing.T) {
	root := [32]byte{0x01}
	txHash := [32]byte{0x02}
	blockNumber := uint64(42)

	got, err := commitmentStructHash(root, txHash, blockNumber)
	if err != nil {
		t.Fatalf("commitmentStructHash err = %v", err)
	}

	// Independent recomputation.
	encoded, err := abi.EncodeArgs(
		[]abi.ABIType{abi.ABITypeBytes32, abi.ABITypeBytes32, abi.ABITypeUint256},
		[]interface{}{root, txHash, new(big.Int).SetUint64(blockNumber)},
	)
	if err != nil {
		t.Fatalf("EncodeArgs: %v", err)
	}
	typeHash := hash.NewKeccak256().Sum([]byte(ProofStructType))
	want := eip712.HashStruct(typeHash[:], encoded)
	if got != want {
		t.Errorf("structHash = %x, want %x", got, want)
	}
}

func TestProof_DigestComposition(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x01}
	txHash := [32]byte{0x02}
	blockNum := uint64(42)

	_, domainHash, err := commitmentDomain(a)
	if err != nil {
		t.Fatalf("commitmentDomain: %v", err)
	}
	structHash, err := commitmentStructHash(root, txHash, blockNum)
	if err != nil {
		t.Fatalf("commitmentStructHash: %v", err)
	}
	composedDigest := eip712.Digest(domainHash, structHash)

	// Hand-assembled: keccak256(0x1901 || domainHash || structHash).
	buf := make([]byte, 0, 2+32+32)
	buf = append(buf, 0x19, 0x01)
	buf = append(buf, domainHash[:]...)
	buf = append(buf, structHash[:]...)
	manualDigest := hash.NewKeccak256().Sum(buf)
	if composedDigest != manualDigest {
		t.Errorf("digest mismatch: %x != %x", composedDigest, manualDigest)
	}
}

func TestProof_TamperDetection(t *testing.T) {
	w := mustWallet(t)
	walletAddr, _ := w.Address()
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x01, 0x02, 0x03}
	r := mustReceipt("0x"+strings.Repeat("aa", 32), 42)

	p, err := Proof(root, a, r, w)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}

	t.Run("tampered root", func(t *testing.T) {
		bad := p
		bad.Root[0] ^= 0xff
		recovered, err := VerifyCommitmentProof(bad)
		if err != nil {
			t.Fatalf("VerifyCommitmentProof err = %v, want nil", err)
		}
		if recovered == walletAddr {
			t.Error("tampered root recovered same address")
		}
	})

	t.Run("tampered txHash", func(t *testing.T) {
		bad := p
		bad.TxHash[0] ^= 0xff
		recovered, err := VerifyCommitmentProof(bad)
		if err != nil {
			t.Fatalf("VerifyCommitmentProof err = %v, want nil", err)
		}
		if recovered == walletAddr {
			t.Error("tampered txHash recovered same address")
		}
	})

	t.Run("tampered blockNumber", func(t *testing.T) {
		bad := p
		bad.BlockNumber = 999
		recovered, err := VerifyCommitmentProof(bad)
		if err != nil {
			t.Fatalf("VerifyCommitmentProof err = %v, want nil", err)
		}
		if recovered == walletAddr {
			t.Error("tampered blockNumber recovered same address")
		}
	})

	t.Run("wrong chain ID", func(t *testing.T) {
		bad := p
		bad.ChainID = big.NewInt(2)
		recovered, err := VerifyCommitmentProof(bad)
		if err != nil {
			t.Fatalf("VerifyCommitmentProof err = %v, want nil", err)
		}
		if recovered == walletAddr {
			t.Error("wrong chain ID recovered same address")
		}
	})
}

func TestVerifyCommitmentProof_BadSignature(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x01}
	r := mustReceipt("0x"+strings.Repeat("aa", 32), 42)

	p, err := Proof(root, a, r, w)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}

	t.Run("truncated signature", func(t *testing.T) {
		bad := p
		bad.Signature = bad.Signature[:64]
		_, err := VerifyCommitmentProof(bad)
		if !errors.Is(err, ErrBadSignature) {
			t.Errorf("err = %v, want ErrBadSignature", err)
		}
	})

	t.Run("invalid recID", func(t *testing.T) {
		bad := p
		sig := make([]byte, 65)
		copy(sig, bad.Signature)
		sig[64] = 99 // recID = 72, invalid
		bad.Signature = sig
		_, err := VerifyCommitmentProof(bad)
		if !errors.Is(err, ErrBadSignature) {
			t.Errorf("err = %v, want ErrBadSignature", err)
		}
	})
}

func TestProof_Failures(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x01}
	goodReceipt := mustReceipt("0x"+strings.Repeat("aa", 32), 42)

	t.Run("nil anchor", func(t *testing.T) {
		_, err := Proof(root, nil, goodReceipt, w)
		if !errors.Is(err, ErrNilAnchor) {
			t.Errorf("err = %v, want ErrNilAnchor", err)
		}
	})

	t.Run("nil wallet", func(t *testing.T) {
		_, err := Proof(root, a, goodReceipt, nil)
		if !errors.Is(err, ErrNilWallet) {
			t.Errorf("err = %v, want ErrNilWallet", err)
		}
	})

	t.Run("short tx hash", func(t *testing.T) {
		r := mustReceipt("0x1234", 42)
		_, err := Proof(root, a, r, w)
		if !errors.Is(err, ErrMalformedReceipt) {
			t.Errorf("err = %v, want ErrMalformedReceipt", err)
		}
	})

	t.Run("non-hex tx hash", func(t *testing.T) {
		r := mustReceipt("0xnothexnotvalidnotvalidnotvalidnotvalidnotvalid12", 42)
		_, err := Proof(root, a, r, w)
		if !errors.Is(err, ErrMalformedReceipt) {
			t.Errorf("err = %v, want ErrMalformedReceipt", err)
		}
	})
}

func TestProof_BlockNumberBoundaries(t *testing.T) {
	w := mustWallet(t)
	walletAddr, _ := w.Address()
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x01}
	txHashStr := "0x" + strings.Repeat("aa", 32)

	for _, bn := range []uint64{0, math.MaxUint64} {
		r := mustReceipt(txHashStr, bn)
		p, err := Proof(root, a, r, w)
		if err != nil {
			t.Fatalf("Proof(blockNum=%d): %v", bn, err)
		}
		recovered, err := VerifyCommitmentProof(p)
		if err != nil {
			t.Fatalf("VerifyCommitmentProof(blockNum=%d): %v", bn, err)
		}
		if recovered != walletAddr {
			t.Errorf("blockNum=%d: recovered %x, want %x", bn, recovered, walletAddr)
		}
	}
}

func TestProof_TxHashWithoutPrefix(t *testing.T) {
	w := mustWallet(t)
	walletAddr, _ := w.Address()
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x01}
	// Bare 64 hex chars without 0x prefix — accepted per task boundary spec.
	r := mustReceipt(strings.Repeat("aa", 32), 42)

	p, err := Proof(root, a, r, w)
	if err != nil {
		t.Fatalf("Proof without 0x prefix: %v", err)
	}
	recovered, err := VerifyCommitmentProof(p)
	if err != nil {
		t.Fatalf("VerifyCommitmentProof: %v", err)
	}
	if recovered != walletAddr {
		t.Errorf("recovered %x, want %x", recovered, walletAddr)
	}
}

func TestProof_SignatureV27V28(t *testing.T) {
	w := mustWallet(t)
	walletAddr, _ := w.Address()
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x01}
	r := mustReceipt("0x"+strings.Repeat("aa", 32), 42)

	p, err := Proof(root, a, r, w)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}

	// The signature's v byte is recID + 27, so it's either 27 or 28.
	v := p.Signature[64]
	if v != 27 && v != 28 {
		t.Fatalf("v = %d, want 27 or 28", v)
	}

	// Flip v between 27 and 28 and verify the other recovers to a
	// different address (wrong recovery id).
	flipped := p
	sig := make([]byte, 65)
	copy(sig, p.Signature)
	if v == 27 {
		sig[64] = 28
	} else {
		sig[64] = 27
	}
	flipped.Signature = sig
	recovered, err := VerifyCommitmentProof(flipped)
	if err != nil {
		t.Fatalf("VerifyCommitmentProof with flipped v: %v", err)
	}
	if recovered == walletAddr {
		t.Error("flipped v recovered same address — one of 27/28 must be wrong")
	}
}
