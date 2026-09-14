package claim

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_NoForbiddenImports verifies the claim package has no
// imports of the auth, chain, kms, signature, attestation, merkle, or
// evidence packages. This enforces the dependency rule: claim may
// import only canonical and authority from this repository.
//
// Forbidden paths are matched as QUOTED import strings (e.g.
// "github.com/bperin/trust/auth" including the quotes) — not raw byte
// containment on the unquoted path — because "auth" is a strict prefix
// of "authority", which this package is required to import. A raw
// substring check would false-positive on the legitimate authority
// import and make the test unpassable.
func TestIsolation_NoForbiddenImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		`"github.com/bperin/trust/auth"`,
		`"github.com/bperin/trust/auth/`,
		`"github.com/bperin/trust/chain"`,
		`"github.com/bperin/trust/chain/`,
		`"github.com/bperin/trust/kms"`,
		`"github.com/bperin/trust/kms/`,
		`"github.com/bperin/trust/signature"`,
		`"github.com/bperin/trust/signature/`,
		`"github.com/bperin/trust/attestation"`,
		`"github.com/bperin/trust/attestation/`,
		`"github.com/bperin/trust/merkle"`,
		`"github.com/bperin/trust/merkle/`,
		`"github.com/bperin/trust/evidence"`,
		`"github.com/bperin/trust/evidence/`,
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
		for _, quoted := range forbidden {
			if strings.Contains(string(data), quoted) {
				t.Errorf("file %s imports %s (dependency rule violation)", path, quoted)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
