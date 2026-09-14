package commitment

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/crypto/hash"
)

// testAddr is a fixed non-zero contract address.
var testAddr = ethereum.Address{0xde, 0xad, 0xbe, 0xef}

// badChainIDs returns chain IDs every anchor constructor must reject.
func badChainIDs() []struct {
	name string
	id   *big.Int
} {
	return []struct {
		name string
		id   *big.Int
	}{
		{"nil", nil},
		{"zero", big.NewInt(0)},
		{"negative", big.NewInt(-1)},
		{"over 256 bits", new(big.Int).Lsh(big.NewInt(1), 256)},
	}
}

func TestNewAnchor(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		a, err := NewAnchor(big.NewInt(1), testAddr)
		if err != nil {
			t.Fatalf("NewAnchor(1, addr) err = %v, want nil", err)
		}
		if a == nil {
			t.Fatal("NewAnchor(1, addr) anchor = nil, want non-nil")
		}
		if a.ChainID.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("ChainID = %v, want 1", a.ChainID)
		}
		if a.Contract != testAddr {
			t.Errorf("Contract = %v, want %v", a.Contract, testAddr)
		}
	})

	t.Run("256-bit boundary accepted", func(t *testing.T) {
		// 2^255 has BitLen 256 — the largest representable chain ID.
		id := new(big.Int).Lsh(big.NewInt(1), 255)
		if _, err := NewAnchor(id, testAddr); err != nil {
			t.Errorf("NewAnchor(2^255, addr) err = %v, want nil", err)
		}
	})

	for _, tc := range badChainIDs() {
		t.Run("bad chain ID/"+tc.name, func(t *testing.T) {
			a, err := NewAnchor(tc.id, testAddr)
			if !errors.Is(err, ErrInvalidAnchor) {
				t.Errorf("NewAnchor err = %v, want ErrInvalidAnchor", err)
			}
			if a != nil {
				t.Errorf("NewAnchor anchor = %v, want nil", a)
			}
		})
	}

	t.Run("zero contract", func(t *testing.T) {
		_, err := NewAnchor(big.NewInt(1), ethereum.Address{})
		if !errors.Is(err, ErrInvalidAnchor) {
			t.Errorf("NewAnchor(1, zero) err = %v, want ErrInvalidAnchor", err)
		}
	})
}

func TestDeriveAnchor_Golden(t *testing.T) {
	got, err := DeriveAnchor(big.NewInt(1), "trust")
	if err != nil {
		t.Fatalf("DeriveAnchor(1, trust) err = %v, want nil", err)
	}

	// Independent recomputation: keccak256("TrustCommitment/" ||
	// "trust" || uint256BE(1)), contract = digest[12:32].
	var id [32]byte
	big.NewInt(1).FillBytes(id[:])
	preimage := append([]byte("TrustCommitment/"), []byte("trust")...)
	preimage = append(preimage, id[:]...)
	digest := hash.NewKeccak256().Sum(preimage)
	var want ethereum.Address
	copy(want[:], digest[12:])
	if !bytes.Equal(got.Contract[:], want[:]) {
		t.Errorf("Contract = %x, want %x (independent recompute)", got.Contract, want)
	}

	// Pinned golden address guards against silent formula changes.
	golden, err := hex.DecodeString("b7e60ad14a19b91e4bd2ad87d890b82f3dba0a60")
	if err != nil {
		t.Fatalf("golden decode: %v", err)
	}
	if !bytes.Equal(got.Contract[:], golden) {
		t.Errorf("Contract = %x, want golden %x", got.Contract, golden)
	}
}

func TestDeriveAnchor_Determinism(t *testing.T) {
	a, err := DeriveAnchor(big.NewInt(1), "trust")
	if err != nil {
		t.Fatalf("first DeriveAnchor err = %v", err)
	}
	b, err := DeriveAnchor(big.NewInt(1), "trust")
	if err != nil {
		t.Fatalf("second DeriveAnchor err = %v", err)
	}
	if !bytes.Equal(a.Contract[:], b.Contract[:]) {
		t.Errorf("same inputs differ: %x != %x", a.Contract, b.Contract)
	}
}

func TestDeriveAnchor_Sensitivity(t *testing.T) {
	base, err := DeriveAnchor(big.NewInt(1), "trust")
	if err != nil {
		t.Fatalf("DeriveAnchor err = %v", err)
	}
	cases := []struct {
		name string
		id   *big.Int
		ns   string
	}{
		{"namespace trust2", big.NewInt(1), "trust2"},
		{"namespace other", big.NewInt(1), "other"},
		{"chain 2", big.NewInt(2), "trust"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			other, err := DeriveAnchor(tc.id, tc.ns)
			if err != nil {
				t.Fatalf("DeriveAnchor(%v, %q) err = %v", tc.id, tc.ns, err)
			}
			if bytes.Equal(base.Contract[:], other.Contract[:]) {
				t.Errorf("DeriveAnchor(%v, %q) = %x, want different from %x",
					tc.id, tc.ns, other.Contract, base.Contract)
			}
		})
	}
}

func TestDeriveAnchor_BadChainID(t *testing.T) {
	for _, tc := range badChainIDs() {
		t.Run(tc.name, func(t *testing.T) {
			a, err := DeriveAnchor(tc.id, "trust")
			if !errors.Is(err, ErrInvalidAnchor) {
				t.Errorf("DeriveAnchor err = %v, want ErrInvalidAnchor", err)
			}
			if a != nil {
				t.Errorf("DeriveAnchor anchor = %v, want nil", a)
			}
		})
	}
}

func TestParseAnchor(t *testing.T) {
	t.Run("round-trip", func(t *testing.T) {
		a, err := ParseAnchor(big.NewInt(1), testAddr.Hex())
		if err != nil {
			t.Fatalf("ParseAnchor err = %v, want nil", err)
		}
		if a.Contract != testAddr {
			t.Errorf("Contract = %v, want %v", a.Contract, testAddr)
		}
	})

	t.Run("all-lowercase accepted", func(t *testing.T) {
		a, err := ParseAnchor(big.NewInt(1), "0xdeadbeef00000000000000000000000000000000")
		if err != nil {
			t.Fatalf("ParseAnchor err = %v, want nil", err)
		}
		if a.Contract != testAddr {
			t.Errorf("Contract = %v, want %v", a.Contract, testAddr)
		}
	})

	t.Run("bad checksum", func(t *testing.T) {
		// Correct checksum is ...1BeAed; flipping the last letter's
		// case keeps it mixed-case but breaks EIP-55.
		_, err := ParseAnchor(big.NewInt(1), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")
		if !errors.Is(err, ethereum.ErrInvalidAddress) {
			t.Errorf("ParseAnchor err = %v, want ethereum.ErrInvalidAddress", err)
		}
	})

	t.Run("bad length", func(t *testing.T) {
		_, err := ParseAnchor(big.NewInt(1), "0xdead")
		if !errors.Is(err, ethereum.ErrInvalidAddress) {
			t.Errorf("ParseAnchor err = %v, want ethereum.ErrInvalidAddress", err)
		}
	})

	for _, tc := range badChainIDs() {
		t.Run("bad chain ID/"+tc.name, func(t *testing.T) {
			_, err := ParseAnchor(tc.id, testAddr.Hex())
			if !errors.Is(err, ErrInvalidAnchor) {
				t.Errorf("ParseAnchor err = %v, want ErrInvalidAnchor", err)
			}
		})
	}
}

func TestAnchor_Validate(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var a *Anchor
		if err := a.Validate(); !errors.Is(err, ErrNilAnchor) {
			t.Errorf("(*Anchor)(nil).Validate() = %v, want ErrNilAnchor", err)
		}
	})

	t.Run("valid", func(t *testing.T) {
		a := &Anchor{ChainID: big.NewInt(1), Contract: testAddr}
		if err := a.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})

	for _, tc := range badChainIDs() {
		t.Run("bad chain ID/"+tc.name, func(t *testing.T) {
			a := &Anchor{ChainID: tc.id, Contract: testAddr}
			if err := a.Validate(); !errors.Is(err, ErrInvalidAnchor) {
				t.Errorf("Validate() = %v, want ErrInvalidAnchor", err)
			}
		})
	}

	t.Run("zero contract", func(t *testing.T) {
		a := &Anchor{ChainID: big.NewInt(1)}
		if err := a.Validate(); !errors.Is(err, ErrInvalidAnchor) {
			t.Errorf("Validate() = %v, want ErrInvalidAnchor", err)
		}
	})
}
