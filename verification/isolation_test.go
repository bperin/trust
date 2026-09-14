package verification

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenImports are the module paths the verification package must
// never import, matched as full quoted import literals.
var forbiddenImports = []string{
	"github.com/bperin/trust/merkle",
	"github.com/bperin/trust/chain",
	"github.com/bperin/trust/kms",
	"github.com/bperin/trust/auth",
}

// TestIsolation_NoForbiddenImports walks the verification package's
// non-test Go files and fails on any forbidden import. Matching is on
// full quoted import literals, so "auth" never false-positives on
// "authority".
func TestIsolation_NoForbiddenImports(t *testing.T) {
	t.Parallel()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", ".git", "testdata":
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
		for _, imp := range forbiddenImports {
			if strings.Contains(string(data), "\""+imp+"\"") {
				t.Errorf("file %s imports %s (dependency rule violation)", path, imp)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// TestIsolation_HelperTable pins the matcher's behavior: forbidden
// quoted literals match, allowed imports and unquoted text do not.
func TestIsolation_HelperTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		body   string
		forbid bool
	}{
		{"merkle import", "import \"github.com/bperin/trust/merkle\"", true},
		{"chain import", "import \"github.com/bperin/trust/chain\"", true},
		{"kms import", "import \"github.com/bperin/trust/kms\"", true},
		{"auth import", "import \"github.com/bperin/trust/auth\"", true},
		{"authority import", "import \"github.com/bperin/trust/authority\"", false},
		{"canonical import", "import \"github.com/bperin/trust/canonical\"", false},
		{"unquoted mention", "// see github.com/bperin/trust/auth for details", false},
	}
	for _, tc := range cases {
		matched := false
		for _, imp := range forbiddenImports {
			if strings.Contains(tc.body, "\""+imp+"\"") {
				matched = true
				break
			}
		}
		if matched != tc.forbid {
			t.Errorf("%s: matched=%v, want %v", tc.name, matched, tc.forbid)
		}
	}
}
