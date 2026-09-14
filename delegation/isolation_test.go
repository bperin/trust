package delegation

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_NoAuthChainKmsImports verifies the delegation package
// has no imports of the auth, chain, kms, or signature packages. This enforces
// the dependency rule: delegation is pure subset logic and imports
// authority only — it never signs, never touches key management, and
// never depends on auth or chain.
//
// The match is exact-path or path-prefix (`auth`, `auth/...`) so the
// legitimate `github.com/bperin/trust/authority` import — which shares
// the `auth` string prefix — is not flagged.
func TestIsolation_NoAuthChainKmsImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"github.com/bperin/trust/auth",
		"github.com/bperin/trust/chain",
		"github.com/bperin/trust/kms",
		"github.com/bperin/trust/signature",
	}

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
		for _, forbiddenPath := range forbidden {
			// Match the exact quoted import `"github.com/bperin/trust/auth"`
			// or a subpackage `"github.com/bperin/trust/auth/..."` — but not
			// `"github.com/bperin/trust/authority"`.
			if strings.Contains(string(data), `"`+forbiddenPath+`"`) ||
				strings.Contains(string(data), `"`+forbiddenPath+`/`) {
				t.Errorf("file %s imports %s (dependency rule violation)", path, forbiddenPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
