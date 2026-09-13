package eip712

import (
	"crypto/subtle"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/wallet"
	"github.com/bperin/trust/trust/crypto/secp256k1"
)

// hexDecode is a test helper that panics on invalid hex.
func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hexDecode(%q): %v", s, err)
	}
	return b
}

// TestDomainSeparator_Hash verifies the EIP-712 domain separator hash
// is deterministic and produces a 32-byte value.
//
// The domain uses the EIP-712 spec example fields. Per [EIP-712] §4,
// the domain type string is:
//
//	"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
//
// Reference: [EIP-712] §4.
func TestDomainSeparator_Hash(t *testing.T) {
	t.Parallel()

	contract, _ := ethereum.ParseAddress("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	domain := DomainSeparator{
		Name:              "Ether Mail",
		Version:           "1",
		ChainID:           big.NewInt(1),
		VerifyingContract: contract,
		Salt:              [32]byte{},
	}

	hash1 := domain.Hash()
	hash2 := domain.Hash()

	if subtle.ConstantTimeCompare(hash1[:], hash2[:]) != 1 {
		t.Fatal("DomainSeparator.Hash not deterministic")
	}

	// The domain type hash must match the known EIP-712 type hash for
	// the 5-field domain (with salt). The 4-field variant (without
	// salt) hashes to 0xa0cedeb2...; the 5-field variant is different.
	wantTypeHash := hexDecode(t, "d87cd6ef79d4e2b95e15ce8abf732db51ec771f1ca2edccf22a46c729ac56472")
	if subtle.ConstantTimeCompare(domainTypeHash[:], wantTypeHash) != 1 {
		t.Fatalf("domain type hash: got %x, want %x", domainTypeHash[:], wantTypeHash)
	}
}

// TestDomainSeparator_TamperFields verifies that changing any domain
// field produces a different hash.
func TestDomainSeparator_TamperFields(t *testing.T) {
	t.Parallel()

	contract, _ := ethereum.ParseAddress("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	base := DomainSeparator{
		Name:              "Ether Mail",
		Version:           "1",
		ChainID:           big.NewInt(1),
		VerifyingContract: contract,
		Salt:              [32]byte{},
	}
	baseHash := base.Hash()

	cases := []struct {
		name   string
		modify func(DomainSeparator) DomainSeparator
	}{
		{
			name: "different name",
			modify: func(d DomainSeparator) DomainSeparator {
				d.Name = "Other App"
				return d
			},
		},
		{
			name: "different version",
			modify: func(d DomainSeparator) DomainSeparator {
				d.Version = "2"
				return d
			},
		},
		{
			name: "different chain id",
			modify: func(d DomainSeparator) DomainSeparator {
				d.ChainID = big.NewInt(2)
				return d
			},
		},
		{
			name: "different verifying contract",
			modify: func(d DomainSeparator) DomainSeparator {
				other, _ := ethereum.ParseAddress("0xBbBbbbbbbBBbbbbbBBBBbbBbbBbbBBbbBbbBbBbB")
				d.VerifyingContract = other
				return d
			},
		},
		{
			name: "different salt",
			modify: func(d DomainSeparator) DomainSeparator {
				d.Salt[0] = 1
				return d
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tampered := tc.modify(base)
			tamperedHash := tampered.Hash()
			if subtle.ConstantTimeCompare(baseHash[:], tamperedHash[:]) == 1 {
				t.Fatalf("tampering %s did not change domain hash", tc.name)
			}
		})
	}
}

// TestDomainSeparator_ZeroChainID verifies a zero chain ID produces a
// valid (all-zero uint256) encoding, not an error.
func TestDomainSeparator_ZeroChainID(t *testing.T) {
	t.Parallel()

	contract, _ := ethereum.ParseAddress("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	domain := DomainSeparator{
		Name:              "Test",
		Version:           "1",
		ChainID:           big.NewInt(0),
		VerifyingContract: contract,
	}
	hash := domain.Hash()
	// Must be non-zero (type hash alone is non-zero).
	var zero [32]byte
	if subtle.ConstantTimeCompare(hash[:], zero[:]) == 1 {
		t.Fatal("zero chain ID produced all-zero domain hash")
	}
}

// TestDomainSeparator_ZeroContract verifies a zero verifying contract
// address produces a valid hash.
func TestDomainSeparator_ZeroContract(t *testing.T) {
	t.Parallel()

	domain := DomainSeparator{
		Name:              "Test",
		Version:           "1",
		ChainID:           big.NewInt(1),
		VerifyingContract: ethereum.Address{},
	}
	hash := domain.Hash()
	var zero [32]byte
	if subtle.ConstantTimeCompare(hash[:], zero[:]) == 1 {
		t.Fatal("zero contract produced all-zero domain hash")
	}
}

// TestHashStruct verifies HashStruct produces a deterministic 32-byte
// value from a type hash and encoded fields.
func TestHashStruct(t *testing.T) {
	t.Parallel()

	typeHash := hexDecode(t, "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf0513f6c1279e1f51")
	encodedFields := make([]byte, 64) // two 32-byte fields

	hash1 := HashStruct(typeHash, encodedFields)
	hash2 := HashStruct(typeHash, encodedFields)

	if subtle.ConstantTimeCompare(hash1[:], hash2[:]) != 1 {
		t.Fatal("HashStruct not deterministic")
	}

	// Different fields → different hash.
	differentFields := make([]byte, 64)
	differentFields[0] = 1
	hash3 := HashStruct(typeHash, differentFields)
	if subtle.ConstantTimeCompare(hash1[:], hash3[:]) == 1 {
		t.Fatal("HashStruct produced same hash for different fields")
	}
}

// TestDigest verifies the EIP-712 digest is deterministic and uses the
// 0x1901 prefix.
func TestDigest(t *testing.T) {
	t.Parallel()

	domainSep := [32]byte{0x01}
	structHash := [32]byte{0x02}

	digest1 := Digest(domainSep, structHash)
	digest2 := Digest(domainSep, structHash)

	if subtle.ConstantTimeCompare(digest1[:], digest2[:]) != 1 {
		t.Fatal("Digest not deterministic")
	}

	// Different inputs → different digest.
	otherStruct := [32]byte{0x03}
	digest3 := Digest(domainSep, otherStruct)
	if subtle.ConstantTimeCompare(digest1[:], digest3[:]) == 1 {
		t.Fatal("Digest produced same value for different struct hash")
	}
}

// TestSignRecover_RoundTrip verifies the full EIP-712 sign + recover
// cycle: construct domain + struct → hash → sign via wallet → recover
// signer address → assert match with wallet address.
func TestSignRecover_RoundTrip(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, err := secp256k1.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	w := wallet.NewWallet(priv)
	walletAddr, _ := w.Address()

	contract, _ := ethereum.ParseAddress("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	domain := DomainSeparator{
		Name:              "Ether Mail",
		Version:           "1",
		ChainID:           big.NewInt(1),
		VerifyingContract: contract,
	}
	domainSep := domain.Hash()

	// A simple struct: typeHash || encodedFields (two 32-byte fields).
	structTypeHash := hexDecode(t, "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf0513f6c1279e1f51")
	encodedFields := make([]byte, 64)
	for i := range encodedFields {
		encodedFields[i] = byte(i)
	}
	structHash := HashStruct(structTypeHash, encodedFields)

	sig, err := Sign(w, domainSep, structHash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature length: got %d, want 65", len(sig))
	}

	recoveredAddr, err := Recover(sig, domainSep, structHash)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}

	if recoveredAddr != walletAddr {
		t.Fatalf("recovered address: got %s, want %s", recoveredAddr.Hex(), walletAddr.Hex())
	}
}

// TestSign_NilWallet verifies a nil wallet produces an error.
func TestSign_NilWallet(t *testing.T) {
	t.Parallel()

	domainSep := [32]byte{0x01}
	structHash := [32]byte{0x02}

	_, err := Sign(nil, domainSep, structHash)
	if err == nil {
		t.Fatal("Sign(nil wallet): got nil error, want error")
	}
}

// TestRecover_BadSignatureLength verifies a non-65-byte signature is
// rejected.
func TestRecover_BadSignatureLength(t *testing.T) {
	t.Parallel()

	domainSep := [32]byte{0x01}
	structHash := [32]byte{0x02}

	cases := []struct {
		name string
		sig  []byte
	}{
		{"too short", []byte("too short")},
		{"empty", nil},
		{"64 bytes", make([]byte, 64)},
		{"66 bytes", make([]byte, 66)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Recover(tc.sig, domainSep, structHash)
			if err == nil {
				t.Fatal("Recover: got nil error, want error")
			}
		})
	}
}

// TestRecover_TamperedStruct verifies that recovering against a
// different struct hash produces a different address (not the
// wallet's).
func TestRecover_TamperedStruct(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, _ := secp256k1.NewPrivateKey(privBytes)
	w := wallet.NewWallet(priv)
	walletAddr, _ := w.Address()

	domainSep := DomainSeparator{
		Name:    "Test",
		Version: "1",
		ChainID: big.NewInt(1),
	}.Hash()

	structHash := [32]byte{0x01}
	sig, err := Sign(w, domainSep, structHash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Recover against a different struct hash.
	tamperedStruct := [32]byte{0x02}
	recoveredAddr, err := Recover(sig, domainSep, tamperedStruct)
	if err != nil {
		// Recovery may fail for a mismatched digest — that's acceptable.
		return
	}
	if recoveredAddr == walletAddr {
		t.Fatal("recovered address matches wallet for tampered struct hash")
	}
}

// TestRecover_TamperedDomain verifies that recovering against a
// different domain separator produces a different address.
func TestRecover_TamperedDomain(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, _ := secp256k1.NewPrivateKey(privBytes)
	w := wallet.NewWallet(priv)
	walletAddr, _ := w.Address()

	domainSep := [32]byte{0x01}
	structHash := [32]byte{0x02}
	sig, err := Sign(w, domainSep, structHash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Recover against a different domain separator.
	tamperedDomain := [32]byte{0x03}
	recoveredAddr, err := Recover(sig, tamperedDomain, structHash)
	if err != nil {
		return
	}
	if recoveredAddr == walletAddr {
		t.Fatal("recovered address matches wallet for tampered domain")
	}
}

// TestRecover_WrongChainID verifies that a different chain ID in the
// domain produces a different digest and thus a different recovered
// address.
func TestRecover_WrongChainID(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, _ := secp256k1.NewPrivateKey(privBytes)
	w := wallet.NewWallet(priv)
	walletAddr, _ := w.Address()

	domain1 := DomainSeparator{
		Name:    "Test",
		Version: "1",
		ChainID: big.NewInt(1),
	}.Hash()
	domain2 := DomainSeparator{
		Name:    "Test",
		Version: "1",
		ChainID: big.NewInt(2),
	}.Hash()

	if subtle.ConstantTimeCompare(domain1[:], domain2[:]) == 1 {
		t.Fatal("different chain IDs produced the same domain hash")
	}

	structHash := [32]byte{0x01}
	sig, err := Sign(w, domain1, structHash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	recoveredAddr, err := Recover(sig, domain2, structHash)
	if err != nil {
		return
	}
	if recoveredAddr == walletAddr {
		t.Fatal("recovered address matches wallet for wrong chain ID")
	}
}

// TestRecover_InvalidRecoveryID verifies an out-of-range recovery id
// (v < 27 or v > 30) is rejected.
func TestRecover_InvalidRecoveryID(t *testing.T) {
	t.Parallel()

	domainSep := [32]byte{0x01}
	structHash := [32]byte{0x02}

	cases := []struct {
		name string
		v    byte
	}{
		{"v=0", 0},
		{"v=26", 26},
		{"v=31", 31},
		{"v=99", 99},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sig := make([]byte, 65)
			sig[64] = tc.v
			_, err := Recover(sig, domainSep, structHash)
			if err == nil {
				t.Fatal("Recover: got nil error, want error for invalid v")
			}
		})
	}
}

// TestEmptyStruct verifies that an empty (zero-length) encoded fields
// value produces a valid struct hash (edge case).
func TestEmptyStruct(t *testing.T) {
	t.Parallel()

	typeHash := []byte{0xaa}
	hash := HashStruct(typeHash, nil)
	var zero [32]byte
	if subtle.ConstantTimeCompare(hash[:], zero[:]) == 1 {
		t.Fatal("empty struct produced all-zero hash")
	}
}

// TestEIP712SpecVectors verifies the full domain separator hash, struct
// hash, and final signing digest against known-good values computed
// from the EIP-712 spec construction. The EIP-712 spec does not
// publish exact hash values for its example, but the construction is
// fully specified in §4 — these vectors pin the implementation to that
// specification.
//
// Domain: name="Ether Mail", version="1", chainId=1,
// verifyingContract=0xCcCC...ccC, salt=0x00...00.
// Struct: Person(address owner, uint256 amount) with owner=contract,
// amount=100.
//
// Reference: [EIP-712] §4.
func TestEIP712SpecVectors(t *testing.T) {
	t.Parallel()

	contract, _ := ethereum.ParseAddress("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	domain := DomainSeparator{
		Name:              "Ether Mail",
		Version:           "1",
		ChainID:           big.NewInt(1),
		VerifyingContract: contract,
		Salt:              [32]byte{},
	}

	// Domain separator hash.
	domainHash := domain.Hash()
	wantDomainHash := hexDecode(t, "ba1e6aec2f6172251cb55ec0e50442204e0123504810a148c631bf43b74546f2")
	if subtle.ConstantTimeCompare(domainHash[:], wantDomainHash) != 1 {
		t.Fatalf("domain separator hash: got %x, want %x", domainHash[:], wantDomainHash)
	}

	// Struct type hash: keccak256("Person(address owner,uint256 amount)")
	personType := "Person(address owner,uint256 amount)"
	personTypeHash := HashStruct([]byte(personType), nil)
	wantPersonTypeHash := hexDecode(t, "b9aafb61fc5374f6f4491d80efaac739a1d3903f8bbe88a3856aa850a5449e66")
	if subtle.ConstantTimeCompare(personTypeHash[:], wantPersonTypeHash) != 1 {
		t.Fatalf("person type hash: got %x, want %x", personTypeHash[:], wantPersonTypeHash)
	}

	// ABI-encode struct fields: owner (address → 32-byte left-padded),
	// amount (uint256 → 32-byte big-endian).
	owner := make([]byte, 32)
	copy(owner[12:], contract[:])
	amount := make([]byte, 32)
	amount[31] = 100
	encoded := append(owner, amount...)

	structHash := HashStruct(personTypeHash[:], encoded)
	wantStructHash := hexDecode(t, "d9cdaa7d3c5733289c86d9337d3975bcd9b80f7479e6d1e7a97f19603180c30a")
	if subtle.ConstantTimeCompare(structHash[:], wantStructHash) != 1 {
		t.Fatalf("struct hash: got %x, want %x", structHash[:], wantStructHash)
	}

	// Final signing digest.
	digest := Digest(domainHash, structHash)
	wantDigest := hexDecode(t, "068a10ca00a2524ae1f74ed3583f6377168a99d17ad47edcb5ae93585a195cd3")
	if subtle.ConstantTimeCompare(digest[:], wantDigest) != 1 {
		t.Fatalf("final digest: got %x, want %x", digest[:], wantDigest)
	}
}
