package didpkh

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/identity/did"
)

const vectorDID = "did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"

func TestResolverResolve(t *testing.T) {
	t.Parallel()

	// Vector: [did:pkh Method Specification] Ethereum account example.
	tests := []struct {
		name  string
		input string
	}{
		{name: "Ethereum mainnet account", input: vectorDID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := mustParseDID(t, tt.input)
			got, err := (&Resolver{}).Resolve(d)
			if err != nil {
				t.Fatalf("Resolve error for input %q: got %v, want nil", tt.input, err)
			}
			if subtle.ConstantTimeCompare([]byte(got.ID), []byte(tt.input)) != 1 {
				t.Errorf("document ID for input %q: got %q, want %q", tt.input, got.ID, tt.input)
			}
			if len(got.VerificationMethod) != 1 {
				t.Fatalf("verification method count for input %q: got %d, want 1", tt.input, len(got.VerificationMethod))
			}
			method := got.VerificationMethod[0]
			if method.Type != "EcdsaSecp256k1RecoveryMethod2020" {
				t.Errorf("verification method type for input %q: got %q, want %q", tt.input, method.Type, "EcdsaSecp256k1RecoveryMethod2020")
			}
			wantMethodID := tt.input + "#blockchainAccountId"
			if subtle.ConstantTimeCompare([]byte(method.ID), []byte(wantMethodID)) != 1 {
				t.Errorf("verification method ID for input %q: got %q, want %q", tt.input, method.ID, wantMethodID)
			}
			if subtle.ConstantTimeCompare([]byte(method.Controller), []byte(tt.input)) != 1 {
				t.Errorf("controller for input %q: got %q, want %q", tt.input, method.Controller, tt.input)
			}
			wantAccount := strings.TrimPrefix(tt.input, "did:pkh:")
			if subtle.ConstantTimeCompare([]byte(method.BlockchainAccountId), []byte(wantAccount)) != 1 {
				t.Errorf("blockchainAccountId for input %q: got %q, want %q", tt.input, method.BlockchainAccountId, wantAccount)
			}
		})
	}
}

func TestResolverResolveErrors(t *testing.T) {
	t.Parallel()

	lower := strings.TrimPrefix(vectorDID, "did:pkh:eip155:1:")
	wrongChecksum := miscaseChecksum(secp256k1.ChecksumAddress(lower))
	tests := []struct {
		name  string
		input string
		want  error
	}{
		{name: "wrong method", input: "did:key:abc", want: ErrWrongMethod},
		{name: "path URL", input: vectorDID + "/keys", want: ErrDIDURLNotSupported},
		{name: "query URL", input: vectorDID + "?versionId=1", want: ErrDIDURLNotSupported},
		{name: "fragment URL", input: vectorDID + "#blockchainAccountId", want: ErrDIDURLNotSupported},
		{name: "missing address component", input: "did:pkh:eip155:1", want: ErrInvalidComponentCount},
		{name: "extra component", input: vectorDID + ":extra", want: ErrInvalidComponentCount},
		{name: "tezos namespace", input: "did:pkh:tezos:mainnet:tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb", want: ErrUnsupportedNamespace},
		{name: "bip122 namespace", input: "did:pkh:bip122:000000000019d6689c085ae165831e93:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", want: ErrUnsupportedNamespace},
		{name: "empty chain reference", input: "did:pkh:eip155::" + lower, want: ErrInvalidChainReference},
		{name: "nondecimal chain reference", input: "did:pkh:eip155:mainnet:" + lower, want: ErrInvalidChainReference},
		{name: "leading-zero chain reference", input: "did:pkh:eip155:01:" + lower, want: ErrInvalidChainReference},
		{name: "41-character address", input: "did:pkh:eip155:1:" + lower[:41], want: ErrMalformedAddress},
		{name: "43-character address", input: "did:pkh:eip155:1:" + lower + "0", want: ErrMalformedAddress},
		{name: "nonhex address", input: "did:pkh:eip155:1:0xg9c5714089478a327f09197987f16f9e5d936e8a", want: ErrMalformedAddress},
		{name: "mixed-case checksum mismatch", input: "did:pkh:eip155:1:" + wrongChecksum, want: ErrChecksumMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := mustParseDID(t, tt.input)
			got, err := (&Resolver{}).Resolve(d)
			if err == nil {
				t.Fatalf("Resolve error for input %q: got nil, want errors.Is(_, %v)", tt.input, tt.want)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("Resolve error class for input %q: got %v, want errors.Is(_, %v)", tt.input, err, tt.want)
			}
			if got != nil {
				t.Errorf("document on failed Resolve for input %q: got %#v, want nil", tt.input, got)
			}
		})
	}
}

func TestParseAccountID(t *testing.T) {
	t.Parallel()

	lower := strings.TrimPrefix(vectorDID, "did:pkh:")
	upperAddress := "0x" + strings.ToUpper(strings.TrimPrefix(lower, "eip155:1:0x"))
	tests := []struct {
		name        string
		input       string
		wantChainID string
		wantAddress string
	}{
		{name: "all-lowercase address", input: lower, wantChainID: "eip155:1", wantAddress: strings.TrimPrefix(lower, "eip155:1:")},
		{name: "all-uppercase address", input: "eip155:1:" + upperAddress, wantChainID: "eip155:1", wantAddress: upperAddress},
		{name: "zero chain reference", input: "eip155:0:" + strings.TrimPrefix(lower, "eip155:1:"), wantChainID: "eip155:0", wantAddress: strings.TrimPrefix(lower, "eip155:1:")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotChainID, gotAddress, err := ParseAccountID(tt.input)
			if err != nil {
				t.Fatalf("ParseAccountID error for input %q: got %v, want nil", tt.input, err)
			}
			if gotChainID != tt.wantChainID {
				t.Errorf("chain ID for input %q: got %q, want %q", tt.input, gotChainID, tt.wantChainID)
			}
			if subtle.ConstantTimeCompare([]byte(gotAddress), []byte(tt.wantAddress)) != 1 {
				t.Errorf("address for input %q: got %q, want %q", tt.input, gotAddress, tt.wantAddress)
			}
		})
	}
}

func TestParseAccountIDErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  error
	}{
		{name: "empty input", input: "", want: ErrInvalidComponentCount},
		{name: "missing address", input: "eip155:1", want: ErrInvalidComponentCount},
		{name: "empty address", input: "eip155:1:", want: ErrMalformedAddress},
		{name: "extra colon", input: "eip155:1:0x00:extra", want: ErrInvalidComponentCount},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotChainID, gotAddress, err := ParseAccountID(tt.input)
			if err == nil {
				t.Fatalf("ParseAccountID error for input %q: got nil, want errors.Is(_, %v)", tt.input, tt.want)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("ParseAccountID error class for input %q: got %v, want errors.Is(_, %v)", tt.input, err, tt.want)
			}
			if gotChainID != "" || gotAddress != "" {
				t.Errorf("outputs on failed ParseAccountID for input %q: got (%q, %q), want (\"\", \"\")", tt.input, gotChainID, gotAddress)
			}
		})
	}
}

func TestDocumentForJSONRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "Ethereum account document", input: vectorDID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			first, err := DocumentFor(mustParseDID(t, tt.input))
			if err != nil {
				t.Fatalf("DocumentFor error for input %q: got %v, want nil", tt.input, err)
			}
			encoded, err := json.Marshal(first)
			if err != nil {
				t.Fatalf("json.Marshal error for input %q: got %v, want nil", tt.input, err)
			}
			var second did.Document
			if err := json.Unmarshal(encoded, &second); err != nil {
				t.Fatalf("json.Unmarshal error for input %q: got %v, want nil", tt.input, err)
			}
			if subtle.ConstantTimeCompare([]byte(second.ID), []byte(first.ID)) != 1 {
				t.Errorf("round-trip document ID for input %q: got %q, want %q", tt.input, second.ID, first.ID)
			}
			if len(second.VerificationMethod) != 1 {
				t.Fatalf("round-trip verification method count for input %q: got %d, want 1", tt.input, len(second.VerificationMethod))
			}
			gotAccount := second.VerificationMethod[0].BlockchainAccountId
			wantAccount := first.VerificationMethod[0].BlockchainAccountId
			if subtle.ConstantTimeCompare([]byte(gotAccount), []byte(wantAccount)) != 1 {
				t.Errorf("round-trip blockchainAccountId for input %q: got %q, want %q", tt.input, gotAccount, wantAccount)
			}
		})
	}
}

func TestDocumentForDeterminism(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "Ethereum account document", input: vectorDID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := mustParseDID(t, tt.input)
			first, err := DocumentFor(d)
			if err != nil {
				t.Fatalf("first DocumentFor error for input %q: got %v, want nil", tt.input, err)
			}
			second, err := DocumentFor(d)
			if err != nil {
				t.Fatalf("second DocumentFor error for input %q: got %v, want nil", tt.input, err)
			}
			firstJSON, err := json.Marshal(first)
			if err != nil {
				t.Fatalf("first json.Marshal error for input %q: got %v, want nil", tt.input, err)
			}
			secondJSON, err := json.Marshal(second)
			if err != nil {
				t.Fatalf("second json.Marshal error for input %q: got %v, want nil", tt.input, err)
			}
			if subtle.ConstantTimeCompare(firstJSON, secondJSON) != 1 {
				t.Errorf("deterministic document JSON for input %q: got %s, want %s", tt.input, secondJSON, firstJSON)
			}
		})
	}
}

func mustParseDID(t *testing.T, input string) did.DID {
	t.Helper()
	d, err := did.Parse(input)
	if err != nil {
		t.Fatalf("did.Parse error for input %q: got %v, want nil", input, err)
	}
	return d
}

func miscaseChecksum(address string) string {
	b := []byte(address)
	for i := 2; i < len(b); i++ {
		if b[i] >= 'a' && b[i] <= 'f' {
			b[i] -= 'a' - 'A'
			return string(b)
		}
		if b[i] >= 'A' && b[i] <= 'F' {
			b[i] += 'a' - 'A'
			return string(b)
		}
	}
	return address
}
