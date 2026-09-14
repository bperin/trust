package kms

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_NoAuthOrChainImports verifies the kms module has no imports
// of the auth or chain sibling modules. This enforces the cross-module
// dependency rule: kms depends on trust only.
//
// Per SPEC-005: kms may import trust only — no chain, no auth.
//
// The legacy pre-monorepo module paths are forbidden too — the old
// github.com/bperin/{auth,chain} modules are still published, so a stale
// import would silently resolve instead of failing the build. The stale
// first-level package paths of the old root trust module
// (github.com/bperin/trust, still published as v0.4.x) are likewise
// forbidden: the trust module now resolves as
// github.com/bperin/trust/trust/... and an import missing the second
// path segment is a regression to the old module.
func TestIsolation_NoAuthOrChainImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		// Current monorepo module paths.
		"github.com/bperin/trust/auth",
		"github.com/bperin/trust/chain",
		// Legacy pre-monorepo module paths.
		"github.com/bperin/auth",
		"github.com/bperin/chain",
		// Stale first-level packages of the old root trust module.
		"github.com/bperin/trust/attestation",
		"github.com/bperin/trust/authority",
		"github.com/bperin/trust/canonical",
		"github.com/bperin/trust/credential",
		"github.com/bperin/trust/crypto",
		"github.com/bperin/trust/evidence",
		"github.com/bperin/trust/identity",
		"github.com/bperin/trust/merkle",
		"github.com/bperin/trust/proof",
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
			if strings.Contains(string(data), forbiddenPath) {
				t.Errorf("file %s imports %s (dependency rule violation)", path, forbiddenPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// TestIsolation_NoCloudAdapterReferences verifies no cloud-provider adapter
// references remain in the kms module. Per PLAN-007 W2 and SPEC-007
// finding A16, the kms/aws and kms/gcp adapter packages moved to the
// private trakt2-crypto repository; the public kms module keeps only the
// RemoteSigner interface and the DER/SPKI parsing core.
//
// The patterns are import-path-shaped, so doc comments that mention
// "AWS KMS" or "GCP KMS" wire formats (der.go, pubkey.go, signer.go) do
// not trip the check. go.mod is scanned in addition to source files: a
// lingering cloud SDK requirement is an adapter reference even when no
// .go file imports it.
func TestIsolation_NoCloudAdapterReferences(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		// Moved adapter packages, current and legacy module paths.
		"github.com/bperin/trust/kms/aws",
		"github.com/bperin/trust/kms/gcp",
		"github.com/bperin/kms/aws",
		"github.com/bperin/kms/gcp",
		// AWS SDKs.
		"github.com/aws/aws-sdk-go",
		"github.com/aws/smithy-go",
		// GCP client libraries.
		"cloud.google.com/go",
		"google.golang.org/api",
		"google.golang.org/genproto",
		"github.com/GoogleCloudPlatform",
	}

	scan := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			return
		}
		for _, bad := range forbidden {
			if strings.Contains(string(data), bad) {
				t.Errorf("file %s references cloud adapter %s (dependency rule violation)", path, bad)
			}
		}
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
		scan(path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	scan("go.mod")
}
