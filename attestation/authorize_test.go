package attestation

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/signature"
)

// eatNow is the shared wall-clock base for test windows. It is
// truncated to whole seconds so an attestation round-trips through
// the EAT codec, which carries times as Unix seconds.
var eatNow = time.Now().UTC().Truncate(time.Second)

// testAuthority returns an active root authority granting the attest
// capability to the attestation's issuer, with a validity window that
// contains the attestation's and the claim's.
func testAuthority() *authority.Authority {
	return &authority.Authority{
		Subject:      "did:example:attester",
		Capabilities: []authority.Capability{authority.CapabilityAttest},
		Scope:        authority.Scope{},
		Validity: authority.Validity{
			NotBefore: eatNow.Add(-time.Hour),
			NotAfter:  eatNow.Add(24 * time.Hour),
		},
		Status: authority.StatusActive,
	}
}

// bindAuthority computes the authority's canonical hash and binds the
// attestation to it: AuthorityRef is set and Issuer is aligned with
// the authority's subject.
func bindAuthority(t *testing.T, att *Attestation, auth *authority.Authority) {
	t.Helper()
	h, err := authority.CanonicalHash(auth)
	if err != nil {
		t.Fatalf("authority.CanonicalHash: %v", err)
	}
	att.AuthorityRef = hex.EncodeToString(h[:])
	att.Issuer = auth.Subject
}

// boundAttestation returns an unsigned attestation whose validity
// windows sit inside the authority's, bound to auth.
func boundAttestation(t *testing.T, auth *authority.Authority) *Attestation {
	t.Helper()
	att := testAttestation(t)
	att.Validity = authority.Validity{
		NotBefore: eatNow.Add(-time.Minute),
		NotAfter:  eatNow.Add(time.Hour),
	}
	att.Claim.Validity = authority.Validity{
		NotBefore: eatNow.Add(-time.Minute),
		NotAfter:  eatNow.Add(time.Hour),
	}
	bindAuthority(t, att, auth)
	return att
}

// signedAttestation returns a validly-signed attestation bound to auth.
func signedAttestation(t *testing.T, auth *authority.Authority) (*Attestation, crypto.PublicKey) {
	t.Helper()
	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := signature.NewLocalSigner(priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	att := boundAttestation(t, auth)
	if err := SignAttestation(context.Background(), att, signer, "leaf-key-1"); err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	return att, pub
}

// TestVerifyAuthorization_Passes asserts the positive single-hop case:
// an active authority granting the exercised capability with
// unconstrained scope and containing validity authorizes the
// attestation.
func TestVerifyAuthorization_Passes(t *testing.T) {
	t.Parallel()

	auth := testAuthority()
	att := boundAttestation(t, auth)
	if err := VerifyAuthorization(att, auth); err != nil {
		t.Fatalf("VerifyAuthorization: got %v, want nil", err)
	}
}

// TestVerifyAuthorization_SentinelTable runs one negative case per
// sentinel, in the order the checks execute. Cases that change the
// authority mutate it before binding so the reference stays valid.
func TestVerifyAuthorization_SentinelTable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		preBind  func(auth *authority.Authority)
		postBind func(att *Attestation)
		wantErr  error
	}{
		{
			name: "empty authority ref",
			postBind: func(att *Attestation) {
				att.AuthorityRef = ""
			},
			wantErr: ErrMissingAuthorityRef,
		},
		{
			name: "substituted authority",
			postBind: func(att *Attestation) {
				att.AuthorityRef = "0000000000000000000000000000000000000000000000000000000000000000"
			},
			wantErr: ErrAuthorityMismatch,
		},
		{
			name: "issuer is not the authority subject",
			postBind: func(att *Attestation) {
				att.Issuer = "did:example:someone-else"
			},
			wantErr: ErrSubjectMismatch,
		},
		{
			name: "capability not granted",
			postBind: func(att *Attestation) {
				att.Capability = authority.CapabilitySign
			},
			wantErr: ErrCapabilityNotGranted,
		},
		{
			name:    "authority not active",
			preBind: func(auth *authority.Authority) { auth.Status = authority.StatusRevoked },
			wantErr: ErrAuthorityNotActive,
		},
		{
			name: "attestation revoked while authority active",
			postBind: func(att *Attestation) {
				att.Status = authority.StatusRevoked
			},
			wantErr: ErrAttestationNotActive,
		},
		{
			name: "attestation superseded while authority active",
			postBind: func(att *Attestation) {
				att.Status = authority.StatusSuperseded
			},
			wantErr: ErrAttestationNotActive,
		},
		{
			name: "attestation expired while authority active",
			postBind: func(att *Attestation) {
				att.Status = authority.StatusExpired
			},
			wantErr: ErrAttestationNotActive,
		},
		{
			name: "attestation validity excludes now inside authority window",
			postBind: func(att *Attestation) {
				att.Validity = authority.Validity{
					NotBefore: eatNow.Add(-2 * time.Hour),
					NotAfter:  eatNow.Add(-30 * time.Minute),
				}
			},
			wantErr: ErrAttestationNotCurrent,
		},
		{
			name: "claim scope exceeds authority scope",
			preBind: func(auth *authority.Authority) {
				auth.Scope = authority.Scope{Resources: []string{"docs"}}
			},
			postBind: func(att *Attestation) {
				// the claim requests a resource outside the
				// authority's single-resource constraint
				att.Claim.Scope = authority.Scope{Resources: []string{"docs", "secrets"}}
			},
			wantErr: ErrAuthorizationScope,
		},
		{
			name: "claim validity outside authority validity",
			postBind: func(att *Attestation) {
				att.Claim.Validity.NotAfter = eatNow.Add(24 * time.Hour).Add(time.Nanosecond)
			},
			wantErr: ErrAuthorizationValidity,
		},
		{
			name: "attestation validity outside authority validity",
			postBind: func(att *Attestation) {
				att.Validity.NotAfter = eatNow.Add(24 * time.Hour).Add(time.Nanosecond)
				att.Claim.Validity.NotAfter = att.Validity.NotAfter
			},
			wantErr: ErrAuthorizationValidity,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			auth := testAuthority()
			if tt.preBind != nil {
				tt.preBind(auth)
			}
			att := boundAttestation(t, auth)
			if tt.postBind != nil {
				tt.postBind(att)
			}
			err := VerifyAuthorization(att, auth)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyAuthorization: got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestVerifyAttestation_BothPass asserts the dual entry point returns
// nil when the signature is valid and the authorization holds.
func TestVerifyAttestation_BothPass(t *testing.T) {
	t.Parallel()

	auth := testAuthority()
	att, pub := signedAttestation(t, auth)
	if err := VerifyAttestation(att, pub, auth); err != nil {
		t.Fatalf("VerifyAttestation: got %v, want nil", err)
	}
}

// TestVerifyAttestation_SignatureValidUnauthorized proves a valid
// signature alone never verifies: the capability is not granted, so
// the dual check fails with ErrCapabilityNotGranted.
func TestVerifyAttestation_SignatureValidUnauthorized(t *testing.T) {
	t.Parallel()

	auth := testAuthority()
	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := signature.NewLocalSigner(priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	att := testAttestation(t)
	att.Capability = authority.CapabilityRevoke // not granted by auth
	bindAuthority(t, att, auth)
	if err := SignAttestation(context.Background(), att, signer, "leaf-key-1"); err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	if err := VerifyAttestation(att, pub, auth); !errors.Is(err, ErrCapabilityNotGranted) {
		t.Fatalf("VerifyAttestation: got %v, want ErrCapabilityNotGranted", err)
	}
}

// TestVerifyAttestation_AuthorizedSignatureInvalid proves an
// authorization-only success is never reported as verified: a
// tampered signature fails the dual check with ErrTamperedAttestation
// even though authorization would pass.
func TestVerifyAttestation_AuthorizedSignatureInvalid(t *testing.T) {
	t.Parallel()

	auth := testAuthority()
	att, pub := signedAttestation(t, auth)
	att.Issuer = "did:example:tampered" // breaks the signature, not the binding
	if err := VerifyAttestation(att, pub, auth); !errors.Is(err, ErrTamperedAttestation) {
		t.Fatalf("VerifyAttestation: got %v, want ErrTamperedAttestation", err)
	}
}

// TestVerifyAttestation_RecoveredEAT is the cross-workstream
// assertion: an attestation recovered via UnmarshalEAT (TASK-072)
// with a valid signature and an authorizing authority passes
// VerifyAttestation.
func TestVerifyAttestation_RecoveredEAT(t *testing.T) {
	t.Parallel()

	auth := testAuthority()
	att, pub := signedAttestation(t, auth)

	token, err := MarshalEAT(att)
	if err != nil {
		t.Fatalf("MarshalEAT: %v", err)
	}
	recovered, err := UnmarshalEAT(token)
	if err != nil {
		t.Fatalf("UnmarshalEAT: %v", err)
	}
	if err := VerifyAttestation(recovered, pub, auth); err != nil {
		t.Fatalf("VerifyAttestation(recovered EAT): got %v, want nil", err)
	}
}

// TestVerifyAttestation_Boundary asserts the containment boundaries:
// equal windows are contained, one nanosecond outside is not.
func TestVerifyAttestation_Boundary(t *testing.T) {
	t.Parallel()

	t.Run("equal validity contained", func(t *testing.T) {
		t.Parallel()
		auth := testAuthority()
		att := testAttestation(t)
		att.Validity = auth.Validity
		att.Claim.Validity = auth.Validity
		bindAuthority(t, att, auth)
		if err := VerifyAuthorization(att, auth); err != nil {
			t.Fatalf("VerifyAuthorization: got %v, want nil", err)
		}
	})
	t.Run("attestation validity one nanosecond outside", func(t *testing.T) {
		t.Parallel()
		auth := testAuthority()
		att := testAttestation(t)
		att.Validity = auth.Validity
		att.Claim.Validity = auth.Validity
		att.Validity.NotAfter = auth.Validity.NotAfter.Add(time.Nanosecond)
		bindAuthority(t, att, auth)
		if err := VerifyAuthorization(att, auth); !errors.Is(err, ErrAuthorizationValidity) {
			t.Fatalf("VerifyAuthorization: got %v, want ErrAuthorizationValidity", err)
		}
	})
	t.Run("claim validity one nanosecond outside", func(t *testing.T) {
		t.Parallel()
		auth := testAuthority()
		att := testAttestation(t)
		att.Validity = authority.Validity{
			NotBefore: eatNow.Add(-time.Minute),
			NotAfter:  eatNow.Add(time.Hour),
		}
		att.Claim.Validity = authority.Validity{
			NotBefore: auth.Validity.NotBefore.Add(-time.Nanosecond),
			NotAfter:  eatNow.Add(time.Hour),
		}
		bindAuthority(t, att, auth)
		if err := VerifyAuthorization(att, auth); !errors.Is(err, ErrAuthorizationValidity) {
			t.Fatalf("VerifyAuthorization: got %v, want ErrAuthorizationValidity", err)
		}
	})
}

// TestVerifyAuthorization_NilAuthorityNeverPanics asserts a nil
// authority pointer errors instead of panicking.
func TestVerifyAuthorization_NilAuthority(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	if err := VerifyAuthorization(att, nil); !errors.Is(err, authority.ErrNilAuthority) {
		t.Fatalf("VerifyAuthorization(nil auth): got %v, want ErrNilAuthority", err)
	}
}
