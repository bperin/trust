package verification

import (
	"errors"
	"testing"

	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/crypto/secp256k1"
)

// runSingleCheck builds a check context for the fixture and runs one
// check, returning the result and error.
func runSingleCheck(t *testing.T, f *fixture, run checkFunc) (*checkContext, error) {
	t.Helper()
	in := f.inputs()
	prov, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	ctx := &checkContext{in: in, now: f.now, prov: prov, e: NewEngine(), hop: -1}
	return ctx, run(ctx)
}

func TestCheckStructural_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if _, err := runSingleCheck(t, f, checkStructural); err != nil {
		t.Errorf("valid fixture failed structural: %v", err)
	}
}

func TestCheckStructural_Malformed(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.att.Issuer = ""
	_, err := runSingleCheck(t, f, checkStructural)
	if !errors.Is(err, ErrStructural) {
		t.Errorf("err = %v, want ErrStructural", err)
	}
}

func TestCheckSignature_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if _, err := runSingleCheck(t, f, checkSignature); err != nil {
		t.Errorf("valid signature failed: %v", err)
	}
}

func TestCheckSignature_Tampered(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.att.Signature[0] ^= 0xFF
	_, err := runSingleCheck(t, f, checkSignature)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("err = %v, want ErrSignatureMismatch", err)
	}
}

func TestCheckSignature_WrongKey(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	// A secp256k1 key resolves to ES256K, not the attestation's EdDSA —
	// the algorithm-confusion defense must reject it.
	_, secpPub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: %v", err)
	}
	in.SigningKey = secpPub
	prov, _ := BuildProvenance(in)
	ctx := &checkContext{in: in, now: f.now, prov: prov, e: NewEngine(), hop: -1}
	err = checkSignature(ctx)
	if !errors.Is(err, ErrSignatureKeyMismatch) {
		t.Errorf("err = %v, want ErrSignatureKeyMismatch", err)
	}
}

func TestCheckAuthorization_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if _, err := runSingleCheck(t, f, checkAuthorization); err != nil {
		t.Errorf("valid authorization failed: %v", err)
	}
}

func TestCheckAuthorization_CapabilityAbsent(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.att.Capability = authority.CapabilityRevoke
	_, err := runSingleCheck(t, f, checkAuthorization)
	if !errors.Is(err, ErrCapabilityNotGranted) {
		t.Errorf("err = %v, want ErrCapabilityNotGranted", err)
	}
}

func TestCheckAuthorization_EscalatedScope(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.att.Claim.Scope.Resources = []string{"secret-resource"}
	_, err := runSingleCheck(t, f, checkAuthorization)
	if !errors.Is(err, ErrScopeViolation) {
		t.Errorf("err = %v, want ErrScopeViolation", err)
	}
}

func TestCheckAuthorization_AuthorityMismatch(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.att.AuthorityRef = "deadbeef"
	_, err := runSingleCheck(t, f, checkAuthorization)
	if !errors.Is(err, ErrAuthorityInvalid) {
		t.Errorf("err = %v, want ErrAuthorityInvalid", err)
	}
}

func TestCheckRootAuthority_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if _, err := runSingleCheck(t, f, checkRootAuthority); err != nil {
		t.Errorf("root authority check failed: %v", err)
	}
}

func TestCheckRootAuthority_NonNilParent(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	parent := "deadbeef"
	f.chain[len(f.chain)-1].Authority.Parent = &parent
	_, err := runSingleCheck(t, f, checkRootAuthority)
	if !errors.Is(err, ErrNotRootAuthority) {
		t.Errorf("err = %v, want ErrNotRootAuthority", err)
	}
}

func TestCheckKeyBinding_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if _, err := runSingleCheck(t, f, checkKeyBinding); err != nil {
		t.Errorf("key binding failed: %v", err)
	}
}

func TestCheckKeyBinding_Mismatch(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	// Swap the attestation signing key for the leaf authority key.
	in := f.inputs()
	in.SigningKey = f.leafPub
	prov, _ := BuildProvenance(in)
	ctx := &checkContext{in: in, now: f.now, prov: prov, e: NewEngine(), hop: -1}
	err := checkKeyBinding(ctx)
	if !errors.Is(err, ErrKeyBinding) {
		t.Errorf("err = %v, want ErrKeyBinding", err)
	}
}

func TestCheckKeyBinding_NoResolverPasses(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.IdentityResolver = nil
	prov, _ := BuildProvenance(in)
	ctx := &checkContext{in: in, now: f.now, prov: prov, e: NewEngine(), hop: -1}
	if err := checkKeyBinding(ctx); err != nil {
		t.Errorf("key binding without resolver should pass, got %v", err)
	}
}
