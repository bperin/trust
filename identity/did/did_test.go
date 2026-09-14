package did

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	// Vector: [W3C DID Test Suite] DID syntax examples.
	tests := []struct {
		name   string
		input  string
		method string
		id     string
	}{
		{name: "basic DID", input: "did:example:123456789abcdefghi", method: "example", id: "123456789abcdefghi"},
		{name: "query", input: "did:example:123456789abcdef?versionId=1", method: "example", id: "123456789abcdef"},
		{name: "fragment", input: "did:example:123#keys-1", method: "example", id: "123"},
		{name: "method digits", input: "did:example123:abc", method: "example123", id: "abc"},
		{name: "multipart identifier", input: "did:example:alpha:beta:gamma", method: "example", id: "alpha:beta:gamma"},
		{name: "percent encoded identifier", input: "did:example:alpha%20beta", method: "example", id: "alpha%20beta"},
		{name: "preserves identifier case", input: "did:example:AbC", method: "example", id: "AbC"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse error for input %q: got %v, want nil", tt.input, err)
			}
			if got.Method() != tt.method {
				t.Errorf("method for input %q: got %q, want %q", tt.input, got.Method(), tt.method)
			}
			if got.MethodSpecificID() != tt.id {
				t.Errorf("method-specific ID for input %q: got %q, want %q", tt.input, got.MethodSpecificID(), tt.id)
			}
			if got.String() != tt.input {
				t.Errorf("round-trip string for input %q: got %q, want %q", tt.input, got.String(), tt.input)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  error
	}{
		{name: "empty", input: "", want: ErrMissingPrefix},
		{name: "missing prefix", input: "example:123", want: ErrMissingPrefix},
		{name: "uppercase scheme", input: "DID:example:123", want: ErrMissingPrefix},
		{name: "scheme only", input: "did:", want: ErrInvalidMethodName},
		{name: "empty method", input: "did::123", want: ErrInvalidMethodName},
		{name: "uppercase method", input: "did:Example:123", want: ErrInvalidMethodName},
		{name: "hyphen in method", input: "did:ex-ample:123", want: ErrInvalidMethodName},
		{name: "missing method separator", input: "did:example", want: ErrInvalidMethodName},
		{name: "empty identifier", input: "did:example:", want: ErrEmptyMethodSpecificID},
		{name: "trailing identifier colon", input: "did:example:123:", want: ErrEmptyMethodSpecificID},
		{name: "empty identifier before URL", input: "did:example:?x=1", want: ErrEmptyMethodSpecificID},
		{name: "invalid identifier tilde", input: "did:example:abc~def", want: ErrInvalidIDChar},
		{name: "invalid identifier space", input: "did:example:abc def", want: ErrInvalidIDChar},
		{name: "invalid UTF-8 byte in identifier", input: "did:example:café", want: ErrInvalidIDChar},
		{name: "incomplete percent encoding", input: "did:example:abc%2", want: ErrInvalidIDChar},
		{name: "nonhex percent encoding", input: "did:example:abc%GG", want: ErrInvalidIDChar},
		{name: "authority component", input: "did:example:123//path", want: ErrAuthorityNotPermitted},
		{name: "second fragment delimiter", input: "did:example:123#one#two", want: ErrInvalidIDChar},
		{name: "invalid path character", input: "did:example:123/path[0]", want: ErrInvalidIDChar},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Parse(tt.input)
			if err == nil {
				t.Fatalf("Parse error for input %q: got nil, want errors.Is(_, %v)", tt.input, tt.want)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("Parse error class for input %q: got %v, want errors.Is(_, %v)", tt.input, err, tt.want)
			}
			if got != (DID{}) {
				t.Errorf("DID on failed parse for input %q: got %#v, want zero value", tt.input, got)
			}
		})
	}
}

func TestDIDURLDecomposition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		path     string
		query    string
		fragment string
	}{
		{name: "path", input: "did:example:123/a/b", path: "/a/b"},
		{name: "query", input: "did:example:123?versionId=1", query: "versionId=1"},
		{name: "fragment", input: "did:example:123#keys-1", fragment: "keys-1"},
		{name: "path query", input: "did:example:123/a?x=1", path: "/a", query: "x=1"},
		{name: "path fragment", input: "did:example:123/a#key", path: "/a", fragment: "key"},
		{name: "query fragment", input: "did:example:123?x=1#key", query: "x=1", fragment: "key"},
		{name: "all components", input: "did:example:123/a/b?x=1#key", path: "/a/b", query: "x=1", fragment: "key"},
		{name: "empty query", input: "did:example:123?", query: ""},
		{name: "empty fragment", input: "did:example:123#", fragment: ""},
		{name: "slash in query per URI ABNF", input: "did:example:123?next=/path", query: "next=/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse error for input %q: got %v, want nil", tt.input, err)
			}
			if got.Path() != tt.path {
				t.Errorf("path for input %q: got %q, want %q", tt.input, got.Path(), tt.path)
			}
			if got.Query() != tt.query {
				t.Errorf("query for input %q: got %q, want %q", tt.input, got.Query(), tt.query)
			}
			if got.Fragment() != tt.fragment {
				t.Errorf("fragment for input %q: got %q, want %q", tt.input, got.Fragment(), tt.fragment)
			}
		})
	}
}

func TestIsDIDAndIsDIDURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantDID    bool
		wantDIDURL bool
	}{
		{name: "bare DID is also a DID URL by ABNF", input: "did:example:123", wantDID: true, wantDIDURL: true},
		{name: "path URL", input: "did:example:123/path", wantDIDURL: true},
		{name: "empty query URL", input: "did:example:123?", wantDIDURL: true},
		{name: "empty fragment URL", input: "did:example:123#", wantDIDURL: true},
		{name: "invalid", input: "DID:example:123"},
		{name: "authority", input: "did:example:123//path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsDID(tt.input); got != tt.wantDID {
				t.Errorf("IsDID for input %q: got %t, want %t", tt.input, got, tt.wantDID)
			}
			if got := IsDIDURL(tt.input); got != tt.wantDIDURL {
				t.Errorf("IsDIDURL for input %q: got %t, want %t", tt.input, got, tt.wantDIDURL)
			}
		})
	}
}

func TestParseDeterminism(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "bare DID", input: "did:example:alpha:beta"},
		{name: "DID URL", input: "did:example:alpha/path?version=1#key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			first, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("first Parse error for input %q: got %v, want nil", tt.input, err)
			}
			second, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("second Parse error for input %q: got %v, want nil", tt.input, err)
			}
			if first != second {
				t.Errorf("deterministic components for input %q: got %#v, want %#v", tt.input, second, first)
			}
		})
	}
}

func TestDocumentJSONRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "verification method and service",
			input: `{"id":"did:example:123","verificationMethod":[{"id":"did:example:123#key-1","type":"JsonWebKey2020","controller":"did:example:123","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYLef..."}}],"service":[{"id":"did:example:123#messages","type":"MessagingService","serviceEndpoint":"https://example.com/messages"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var first Document
			if err := json.Unmarshal([]byte(tt.input), &first); err != nil {
				t.Fatalf("json.Unmarshal for input %q: got %v, want nil", tt.input, err)
			}
			encoded, err := json.Marshal(first)
			if err != nil {
				t.Fatalf("json.Marshal for input %q: got %v, want nil", tt.input, err)
			}
			var second Document
			if err := json.Unmarshal(encoded, &second); err != nil {
				t.Fatalf("round-trip json.Unmarshal for input %q: got %v, want nil", tt.input, err)
			}
			if !reflect.DeepEqual(second, first) {
				t.Errorf("document after JSON round-trip for input %q: got %#v, want %#v", tt.input, second, first)
			}
		})
	}
}

func TestResolverInterface(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		impl Resolver
	}{
		{name: "local resolver satisfies interface", impl: resolverStub{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d, err := Parse("did:example:123")
			if err != nil {
				t.Fatalf("Parse error for resolver input %q: got %v, want nil", "did:example:123", err)
			}
			got, err := tt.impl.Resolve(d)
			if err != nil {
				t.Fatalf("Resolve error for input %q: got %v, want nil", d.String(), err)
			}
			if got.ID != d.String() {
				t.Errorf("resolved document ID for input %q: got %q, want %q", d.String(), got.ID, d.String())
			}
		})
	}
}

type resolverStub struct{}

func (resolverStub) Resolve(d DID) (*Document, error) {
	return &Document{ID: d.String()}, nil
}
