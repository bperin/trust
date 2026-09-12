package evidence

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// mustDecodeHash decodes a hex-encoded SHA-256 test vector into [32]byte.
func mustDecodeHash(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid test vector hex: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("test vector is %d bytes, want 32", len(b))
	}
	var h [32]byte
	copy(h[:], b)
	return h
}

func TestHashContent_KnownVectors(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string // hex SHA-256
	}{
		{
			// Vector: [FIPS 180-4] §B.1 — SHA-256("abc").
			name: "abc",
			in:   []byte("abc"),
			want: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		{
			// Vector: [FIPS 180-4] §B.2 — SHA-256 of the 56-byte
			// multi-block message.
			name: "multi-block",
			in:   []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
			want: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
		},
		{
			// Vector: [FIPS 180-4] — SHA-256 of the empty string.
			name: "empty",
			in:   []byte{},
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			// Boundary: nil input hashes identically to empty input.
			name: "nil",
			in:   nil,
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashContent(tt.in)
			want := mustDecodeHash(t, tt.want)
			if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				t.Errorf("HashContent(%q)\n got = %x\nwant = %s", tt.in, got, tt.want)
			}
		})
	}
}

func TestHashContent_Determinism(t *testing.T) {
	content := []byte("evidence payload")
	h1 := HashContent(content)
	for i := 0; i < 10; i++ {
		h2 := HashContent(content)
		if subtle.ConstantTimeCompare(h1[:], h2[:]) != 1 {
			t.Fatalf("run %d: HashContent not deterministic:\n a = %x\n b = %x", i, h1, h2)
		}
	}
}

func TestVerifyContent(t *testing.T) {
	content := []byte("evidence payload")
	h := HashContent(content)
	deadURI := "https://example.invalid/missing.pdf"

	tests := []struct {
		name    string
		ref     EvidenceRef
		content []byte
		wantErr error
	}{
		{
			// Round-trip: hash content, build ref, verify.
			name:    "round-trip",
			ref:     EvidenceRef{Type: "json", URI: "https://example.com/e.json", ContentHash: h},
			content: content,
			wantErr: nil,
		},
		{
			// Negative: the URI is dead, but content obtained from
			// another source still verifies — the URI is advisory.
			name:    "dead URI correct content",
			ref:     EvidenceRef{Type: "pdf", URI: deadURI, ContentHash: h},
			content: content,
			wantErr: nil,
		},
		{
			// A reference with no URI at all still verifies — the URI
			// is never part of the identity.
			name:    "empty URI",
			ref:     EvidenceRef{Type: "pdf", ContentHash: h},
			content: content,
			wantErr: nil,
		},
		{
			// Negative: dead URI with wrong content fails by hash,
			// not because the link is dead.
			name:    "dead URI wrong content",
			ref:     EvidenceRef{Type: "pdf", URI: deadURI, ContentHash: h},
			content: []byte("tampered evidence"),
			wantErr: ErrContentHashMismatch,
		},
		{
			name:    "tampered content",
			ref:     EvidenceRef{Type: "json", URI: "https://example.com/e.json", ContentHash: h},
			content: []byte("evidence payloae"),
			wantErr: ErrContentHashMismatch,
		},
		{
			// Boundary: empty content does not match a hash of
			// non-empty content.
			name:    "empty content against non-empty hash",
			ref:     EvidenceRef{ContentHash: h},
			content: nil,
			wantErr: ErrContentHashMismatch,
		},
		{
			// Negative: zero ContentHash is a missing identity, not
			// a mismatch.
			name:    "missing hash",
			ref:     EvidenceRef{Type: "pdf", URI: deadURI},
			content: content,
			wantErr: ErrMissingContentHash,
		},
		{
			name:    "missing hash zero ref",
			ref:     EvidenceRef{},
			content: nil,
			wantErr: ErrMissingContentHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyContent(tt.ref, tt.content)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("VerifyContent(%+v, %q) error = %v, want %v", tt.ref, tt.content, err, tt.wantErr)
			}
		})
	}
}

func TestVerifyContent_EmptyContent(t *testing.T) {
	// Boundary: a reference to empty content verifies against both nil
	// and zero-length input — both produce the SHA-256 of "".
	ref := EvidenceRef{Type: "json", ContentHash: HashContent(nil)}

	for _, content := range [][]byte{nil, {}} {
		if err := VerifyContent(ref, content); err != nil {
			t.Errorf("VerifyContent(empty ref, %v) error = %v, want nil", content, err)
		}
	}
}

func TestVerifyContent_MismatchUniformity(t *testing.T) {
	// The comparison must not leak where the digests differed: content
	// whose hash differs from the reference in the first byte and content
	// whose hash differs in the last byte produce the identical sentinel
	// error — there is no early-exit distinction.
	content := []byte("evidence payload")
	ref := EvidenceRef{ContentHash: HashContent(content)}

	err1 := VerifyContent(ref, []byte("xvidence payload"))
	err2 := VerifyContent(ref, []byte("evidence payloax"))

	if !errors.Is(err1, ErrContentHashMismatch) {
		t.Errorf("first-byte mismatch error = %v, want ErrContentHashMismatch", err1)
	}
	if !errors.Is(err2, ErrContentHashMismatch) {
		t.Errorf("last-byte mismatch error = %v, want ErrContentHashMismatch", err2)
	}
	if err1 != err2 {
		t.Errorf("mismatch errors differ:\n first = %v\n last = %v", err1, err2)
	}
}

// TestConstantTimeComparison asserts that evidence.go compares digests
// with crypto/subtle.ConstantTimeCompare — never == or bytes.Equal.
func TestConstantTimeComparison(t *testing.T) {
	src, err := os.ReadFile("evidence.go")
	if err != nil {
		t.Fatalf("read evidence.go: %v", err)
	}
	if !strings.Contains(string(src), "subtle.ConstantTimeCompare") {
		t.Error("evidence.go does not use subtle.ConstantTimeCompare")
	}
	if strings.Contains(string(src), "bytes.Equal") {
		t.Error("evidence.go uses bytes.Equal for digest comparison")
	}
}

// TestNoAuthOrChainImports enforces the dependency rule: trust/evidence
// must not import auth/ or chain/.
func TestNoAuthOrChainImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, name := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", name, err)
			}
			for _, bad := range []string{"github.com/bperin/auth", "github.com/bperin/chain"} {
				if path == bad || strings.HasPrefix(path, bad+"/") {
					t.Errorf("%s imports forbidden module %s", name, path)
				}
			}
		}
	}
}
