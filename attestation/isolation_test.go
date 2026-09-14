package attestation

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenAttestationImports are the packages attestation/ must
// never import: the crypto core stays independent of the consumer
// packages per the dependency rule in AGENTS.md.
var forbiddenAttestationImports = []string{
	"github.com/bperin/trust/auth",
	"github.com/bperin/trust/chain",
	"github.com/bperin/trust/kms",
	"github.com/bperin/trust/delegation",
	"github.com/bperin/trust/merkle",
}

// hasForbiddenImport reports whether data contains a full quoted
// import of a forbidden package, returning the matched import. The
// surrounding quotes prevent "github.com/bperin/trust/auth" from
// matching the legitimate "github.com/bperin/trust/authority" import.
func hasForbiddenImport(data []byte) (string, bool) {
	for _, forbidden := range forbiddenAttestationImports {
		quoted := `"` + forbidden + `"`
		if bytes.Contains(data, []byte(quoted)) {
			return quoted, true
		}
	}
	return "", false
}

// TestIsolation_NoForbiddenImports walks every non-test .go file
// under attestation/ and fails if any file imports auth/, chain/,
// kms/, delegation/, or merkle/. This is the negative gate for the
// attestation package's dependency isolation: if a forbidden import
// is introduced, this test fails.
func TestIsolation_NoForbiddenImports(t *testing.T) {
	t.Parallel()

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == ".git" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if match, ok := hasForbiddenImport(data); ok {
			t.Errorf("file %s imports %s (dependency rule violation)", path, match)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// TestIsolation_HelperTable proves the matching helper detects full
// quoted forbidden imports and ignores the allowed imports whose
// paths merely contain a forbidden prefix — the auth/authority case
// that motivates quoted-literal matching.
func TestIsolation_HelperTable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		wantMatched bool
	}{
		{
			name:        "forbidden auth import",
			body:        "package p\nimport \"github.com/bperin/trust/auth\"\n",
			wantMatched: true,
		},
		{
			name:        "forbidden chain import",
			body:        "package p\nimport \"github.com/bperin/trust/chain\"\n",
			wantMatched: true,
		},
		{
			name:        "forbidden kms import",
			body:        "package p\nimport \"github.com/bperin/trust/kms\"\n",
			wantMatched: true,
		},
		{
			name:        "forbidden delegation import",
			body:        "package p\nimport \"github.com/bperin/trust/delegation\"\n",
			wantMatched: true,
		},
		{
			name:        "forbidden merkle import",
			body:        "package p\nimport \"github.com/bperin/trust/merkle\"\n",
			wantMatched: true,
		},
		{
			name:        "allowed authority import is not a false positive",
			body:        "package p\nimport \"github.com/bperin/trust/authority\"\n",
			wantMatched: false,
		},
		{
			name:        "allowed canonical import",
			body:        "package p\nimport \"github.com/bperin/trust/canonical\"\n",
			wantMatched: false,
		},
		{
			name:        "allowed signature import",
			body:        "package p\nimport \"github.com/bperin/trust/signature\"\n",
			wantMatched: false,
		},
		{
			name:        "unquoted path in comment does not match",
			body:        "package p\n// see github.com/bperin/trust/auth for docs\n",
			wantMatched: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			match, got := hasForbiddenImport([]byte(tt.body))
			if got != tt.wantMatched {
				t.Fatalf("hasForbiddenImport: got matched=%v (match %q), want matched=%v", got, match, tt.wantMatched)
			}
		})
	}
}
