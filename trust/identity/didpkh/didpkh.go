package didpkh

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/identity/did"
)

// Sentinel errors returned by Resolver, DocumentFor, and ParseAccountID. Check
// them with errors.Is.
var (
	// ErrWrongMethod identifies a DID whose method is not "pkh".
	ErrWrongMethod = errors.New("didpkh: wrong DID method")
	// ErrDIDURLNotSupported identifies a DID URL passed where a bare did:pkh DID is required.
	ErrDIDURLNotSupported = errors.New("didpkh: DID URLs are not supported")
	// ErrInvalidComponentCount identifies a method-specific identifier that does not have three CAIP-10 components.
	ErrInvalidComponentCount = errors.New("didpkh: invalid account identifier component count")
	// ErrUnsupportedNamespace identifies a CAIP-10 namespace other than eip155.
	ErrUnsupportedNamespace = errors.New("didpkh: unsupported CAIP-10 namespace")
	// ErrInvalidChainReference identifies an eip155 reference that is not a canonical nonnegative decimal integer.
	ErrInvalidChainReference = errors.New("didpkh: invalid eip155 chain reference")
	// ErrMalformedAddress identifies an account address that is not exactly 20 hexadecimal bytes with a 0x prefix.
	ErrMalformedAddress = errors.New("didpkh: malformed Ethereum address")
	// ErrChecksumMismatch identifies a mixed-case Ethereum address that does not match its EIP-55 checksum.
	ErrChecksumMismatch = errors.New("didpkh: EIP-55 checksum mismatch")
)

// Resolver implements the [did:pkh Method Specification] for local, stateless
// resolution of eip155 blockchain account DIDs.
type Resolver struct{}

var _ did.Resolver = (*Resolver)(nil)

// Resolve implements the [did:pkh Method Specification] — it resolves a bare
// eip155 did:pkh DID into its deterministic DID document.
func (r *Resolver) Resolve(d did.DID) (*did.Document, error) {
	doc, err := DocumentFor(d)
	if err != nil {
		return nil, fmt.Errorf("resolve did:pkh %q: %w", d.String(), err)
	}
	return doc, nil
}

// ParseAccountID implements [CAIP-10] — it validates an eip155 account ID and
// returns its CAIP-2 chain ID and exact original account address. On failure it
// returns empty strings and an error wrapping the applicable sentinel.
func ParseAccountID(s string) (chainID, address string, err error) {
	colonCount := strings.Count(s, ":")
	if colonCount != 2 {
		return "", "", fmt.Errorf("parse CAIP-10 account %q: %w: got %d components, want 3", s, ErrInvalidComponentCount, colonCount+1)
	}

	parts := strings.Split(s, ":")
	namespace, reference, account := parts[0], parts[1], parts[2]
	if namespace != "eip155" {
		return "", "", fmt.Errorf("parse CAIP-10 account %q: %w %q", s, ErrUnsupportedNamespace, namespace)
	}
	if !validChainReference(reference) {
		return "", "", fmt.Errorf("parse CAIP-10 account %q: %w %q", s, ErrInvalidChainReference, reference)
	}
	if err := validateAddress(account); err != nil {
		return "", "", fmt.Errorf("parse CAIP-10 account %q: %w", s, err)
	}

	return namespace + ":" + reference, account, nil
}

// DocumentFor implements the [did:pkh Method Specification] — it validates d
// and constructs the deterministic eip155 DID document while preserving the
// exact original DID and account identifier spelling.
func DocumentFor(d did.DID) (*did.Document, error) {
	if d.Path() != "" || d.Query() != "" || d.Fragment() != "" || (d.String() != "" && !did.IsDID(d.String())) {
		return nil, fmt.Errorf("build document for %q: %w", d.String(), ErrDIDURLNotSupported)
	}
	if d.Method() != "pkh" {
		return nil, fmt.Errorf("build document for %q: %w: got %q, want %q", d.String(), ErrWrongMethod, d.Method(), "pkh")
	}
	if _, _, err := ParseAccountID(d.MethodSpecificID()); err != nil {
		return nil, fmt.Errorf("build document for %q: %w", d.String(), err)
	}

	id := d.String()
	return &did.Document{
		ID: id,
		VerificationMethod: []did.Method{
			{
				ID:                  id + "#blockchainAccountId",
				Type:                "EcdsaSecp256k1RecoveryMethod2020",
				Controller:          id,
				BlockchainAccountId: d.MethodSpecificID(),
			},
		},
	}, nil
}

func validChainReference(reference string) bool {
	if reference == "" || (len(reference) > 1 && reference[0] == '0') {
		return false
	}
	for i := 0; i < len(reference); i++ {
		if reference[i] < '0' || reference[i] > '9' {
			return false
		}
	}
	return true
}

func validateAddress(address string) error {
	if len(address) != 42 || !strings.HasPrefix(address, "0x") {
		return fmt.Errorf("%w %q: got length %d, want 42 characters with 0x prefix", ErrMalformedAddress, address, len(address))
	}
	payload := address[2:]
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("%w %q: non-hexadecimal character at offset %d", ErrMalformedAddress, address, i+2)
		}
	}

	if payload == strings.ToLower(payload) || payload == strings.ToUpper(payload) {
		return nil
	}
	canonical := secp256k1.ChecksumAddress(address)
	if subtle.ConstantTimeCompare([]byte(address), []byte(canonical)) != 1 {
		return fmt.Errorf("%w: input %q, canonical %q", ErrChecksumMismatch, address, canonical)
	}
	return nil
}
