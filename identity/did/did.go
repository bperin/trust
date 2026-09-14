package did

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by Parse. Check them with errors.Is.
var (
	// ErrMissingPrefix identifies a [W3C DID-CORE v1.0] §3.1 violation in which an
	// identifier lacks the required case-sensitive "did:" scheme.
	ErrMissingPrefix = errors.New("did: missing did: prefix")
	// ErrInvalidMethodName identifies a [W3C DID-CORE v1.0] §3.1 violation in which
	// a method name is empty or contains a character other than a lowercase
	// ASCII letter or digit.
	ErrInvalidMethodName = errors.New("did: invalid method name")
	// ErrEmptyMethodSpecificID identifies a [W3C DID-CORE v1.0] §3.1 violation in
	// which the method-specific identifier is empty or ends with an empty
	// colon-delimited segment.
	ErrEmptyMethodSpecificID = errors.New("did: empty method-specific identifier")
	// ErrInvalidIDChar identifies a [W3C DID-CORE v1.0] §3.1 violation in which a
	// DID or DID URL contains a character outside the ABNF, including malformed
	// percent encoding.
	ErrInvalidIDChar = errors.New("did: invalid identifier character")
	// ErrAuthorityNotPermitted identifies a [W3C DID-CORE v1.0] §3.2 violation in
	// which a DID URL path starts with "//" and would introduce an authority.
	ErrAuthorityNotPermitted = errors.New("did: authority component not permitted")
)

const (
	charMethod byte = 1 << iota
	charID
	charUnreserved
	charSubDelim
	charHex
)

var didCharset = func() [256]byte {
	var table [256]byte
	for c := byte('a'); c <= 'z'; c++ {
		table[c] |= charMethod | charID | charUnreserved
	}
	for c := byte('A'); c <= 'Z'; c++ {
		table[c] |= charID | charUnreserved
	}
	for c := byte('0'); c <= '9'; c++ {
		table[c] |= charMethod | charID | charUnreserved | charHex
	}
	for c := byte('a'); c <= 'f'; c++ {
		table[c] |= charHex
	}
	for c := byte('A'); c <= 'F'; c++ {
		table[c] |= charHex
	}
	for _, c := range []byte("-._") {
		table[c] |= charID | charUnreserved
	}
	table['~'] |= charUnreserved
	for _, c := range []byte("!$&'()*+,;=") {
		table[c] |= charSubDelim
	}
	return table
}()

// DID implements [W3C DID-CORE v1.0] §3 — an immutable decentralized identifier
// and, when present, its URL path, query, and fragment components. Parsed
// components are zero-copy substrings of the original input.
type DID struct {
	original         string
	method           string
	methodSpecificID string
	path             string
	query            string
	fragment         string
	isURL            bool
}

// Document implements [W3C DID-CORE v1.0] §5 — the core properties of a DID
// document used by local method-specific resolvers.
type Document struct {
	// ID is the DID subject identified by the document.
	ID string `json:"id"`
	// VerificationMethod contains public-key and other verification methods.
	VerificationMethod []Method `json:"verificationMethod,omitempty"`
	// Service contains ways of communicating with or interacting with the subject.
	Service []Service `json:"service,omitempty"`
}

// Method implements [W3C DID-CORE v1.0] §5.2 — a verification method containing
// its identifier, type, controller, and public verification material.
type Method struct {
	// ID is the verification method identifier.
	ID string `json:"id"`
	// Type identifies the verification method suite.
	Type string `json:"type"`
	// Controller identifies the entity controlling this verification method.
	Controller string `json:"controller"`
	// BlockchainAccountId implements [W3C DID-SPEC-REGISTRIES] — it identifies
	// the controlling blockchain account using a CAIP-10 account identifier.
	BlockchainAccountId string `json:"blockchainAccountId,omitempty"`
	// PublicKeyJWK contains public verification material as a JSON Web Key.
	PublicKeyJWK map[string]any `json:"publicKeyJwk,omitempty"`
	// PublicKeyMultibase contains multibase-encoded public verification material.
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}

// Service implements [W3C DID-CORE v1.0] §5.4 — a service advertised by a DID
// document. ServiceEndpoint accepts the string, map, or array forms permitted
// by the data model.
type Service struct {
	// ID is the service identifier.
	ID string `json:"id"`
	// Type identifies the kind of service.
	Type string `json:"type"`
	// ServiceEndpoint is the URI or structured endpoint used to access the service.
	ServiceEndpoint any `json:"serviceEndpoint"`
}

// Resolver implements [W3C DID-CORE v1.0] §7 — the local contract implemented by
// method-specific DID resolvers. The core package performs no network calls.
type Resolver interface {
	// Resolve implements [W3C DID-CORE v1.0] §7 — it applies a method-specific
	// resolution operation to did.
	Resolve(did DID) (*Document, error)
}

// Parse implements [W3C DID-CORE v1.0] §3.1 — it validates and decomposes a DID or
// DID URL in one pass. On failure Parse returns a zero-value DID and an error
// wrapping the applicable sentinel.
func Parse(s string) (DID, error) {
	d, err := parse(s)
	if err != nil {
		return DID{}, fmt.Errorf("parse DID %q: %w", s, err)
	}
	return d, nil
}

// String implements [W3C DID-CORE v1.0] §3 serialization — it returns the exact
// original spelling supplied to Parse. The zero-value DID serializes as "".
func (d DID) String() string {
	return d.original
}

// Method implements [W3C DID-CORE v1.0] §3.1 — it returns the method-name component
// while preserving its original spelling.
func (d DID) Method() string {
	return d.method
}

// MethodSpecificID implements [W3C DID-CORE v1.0] §3.1 — it returns the complete
// method-specific-id component while preserving its original spelling.
func (d DID) MethodSpecificID() string {
	return d.methodSpecificID
}

// Path implements [W3C DID-CORE v1.0] §3.2 — it returns the DID URL path, including
// its leading slash, or "" when no path is present.
func (d DID) Path() string {
	return d.path
}

// Query implements [W3C DID-CORE v1.0] §3.2 — it returns the DID URL query without
// the leading question mark, or "" when absent or empty.
func (d DID) Query() string {
	return d.query
}

// Fragment implements [W3C DID-CORE v1.0] §3.2 — it returns the DID URL fragment
// without the leading number sign, or "" when absent or empty.
func (d DID) Fragment() string {
	return d.fragment
}

// IsDID implements [W3C DID-CORE v1.0] §3.1 — it reports whether s is a valid bare
// DID with no path, query, or fragment.
func IsDID(s string) bool {
	d, err := parse(s)
	return err == nil && !d.isURL
}

// IsDIDURL implements [W3C DID-CORE v1.0] §3.2 — it reports whether s conforms to
// the DID URL ABNF. A bare DID is also a valid DID URL because every URL
// component in that grammar is optional.
func IsDIDURL(s string) bool {
	_, err := parse(s)
	return err == nil
}

// parse validates s against the [W3C DID-CORE v1.0] §3.1 ABNF in a single
// left-to-right pass and records component boundaries without copying. It
// returns bare sentinels so internal callers skip error wrapping.
func parse(s string) (DID, error) {
	if len(s) < 4 || s[0] != 'd' || s[1] != 'i' || s[2] != 'd' || s[3] != ':' {
		return DID{}, ErrMissingPrefix
	}

	const (
		stateMethod = iota
		stateID
		statePath
		stateQuery
		stateFragment
	)

	state := stateMethod
	methodStart := 4
	methodEnd := -1
	idStart := -1
	idEnd := -1
	pathStart := -1
	queryStart := -1
	fragmentStart := -1
	url := false

	for i := 4; i < len(s); i++ {
		c := s[i]
		switch state {
		case stateMethod:
			if c == ':' {
				if i == methodStart {
					return DID{}, ErrInvalidMethodName
				}
				methodEnd = i
				idStart = i + 1
				state = stateID
				continue
			}
			if didCharset[c]&charMethod == 0 {
				return DID{}, ErrInvalidMethodName
			}
		case stateID:
			switch c {
			case '/', '?', '#':
				if i == idStart || s[i-1] == ':' {
					return DID{}, ErrEmptyMethodSpecificID
				}
				idEnd = i
				url = true
				switch c {
				case '/':
					if i+1 < len(s) && s[i+1] == '/' {
						return DID{}, ErrAuthorityNotPermitted
					}
					pathStart = i
					state = statePath
				case '?':
					queryStart = i + 1
					state = stateQuery
				case '#':
					fragmentStart = i + 1
					state = stateFragment
				}
				continue
			case ':':
				continue
			}
			next, ok := validEscapedOr(c, s, i, charID)
			if !ok {
				return DID{}, ErrInvalidIDChar
			}
			i = next
		case statePath:
			switch c {
			case '?':
				queryStart = i + 1
				state = stateQuery
				continue
			case '#':
				fragmentStart = i + 1
				state = stateFragment
				continue
			case '/', ':', '@':
				continue
			}
			next, ok := validEscapedOr(c, s, i, charUnreserved|charSubDelim)
			if !ok {
				return DID{}, ErrInvalidIDChar
			}
			i = next
		case stateQuery:
			if c == '#' {
				fragmentStart = i + 1
				state = stateFragment
				continue
			}
			if c == '/' || c == '?' || c == ':' || c == '@' {
				continue
			}
			next, ok := validEscapedOr(c, s, i, charUnreserved|charSubDelim)
			if !ok {
				return DID{}, ErrInvalidIDChar
			}
			i = next
		case stateFragment:
			if c == '/' || c == '?' || c == ':' || c == '@' {
				continue
			}
			next, ok := validEscapedOr(c, s, i, charUnreserved|charSubDelim)
			if !ok {
				return DID{}, ErrInvalidIDChar
			}
			i = next
		}
	}

	if state == stateMethod {
		return DID{}, ErrInvalidMethodName
	}
	// Empty method-specific-id: either nothing follows the method colon, or
	// the id ends with an empty colon-delimited segment.
	if idStart == len(s) || (idEnd < 0 && s[len(s)-1] == ':') {
		return DID{}, ErrEmptyMethodSpecificID
	}
	if idEnd < 0 {
		idEnd = len(s)
	}

	d := DID{
		original:         s,
		method:           s[methodStart:methodEnd],
		methodSpecificID: s[idStart:idEnd],
		isURL:            url,
	}
	if pathStart >= 0 {
		end := len(s)
		if queryStart >= 0 {
			end = queryStart - 1
		} else if fragmentStart >= 0 {
			end = fragmentStart - 1
		}
		d.path = s[pathStart:end]
	}
	if queryStart >= 0 {
		end := len(s)
		if fragmentStart >= 0 {
			end = fragmentStart - 1
		}
		d.query = s[queryStart:end]
	}
	if fragmentStart >= 0 {
		d.fragment = s[fragmentStart:]
	}
	return d, nil
}

// validEscapedOr reports whether s[i] is acceptable under mask, accepting a
// percent-encoded triplet when the next two bytes are hexadecimal. It returns
// the index of the last consumed byte.
func validEscapedOr(c byte, s string, i int, mask byte) (int, bool) {
	if c != '%' {
		return i, didCharset[c]&mask != 0
	}
	if i+2 >= len(s) || didCharset[s[i+1]]&charHex == 0 || didCharset[s[i+2]]&charHex == 0 {
		return i, false
	}
	return i + 2, true
}
