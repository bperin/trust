package commitment

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/claim"
	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/evidence"
)

func TestLeafHash_AdapterDelegation(t *testing.T) {
	auth := &authority.Authority{Subject: "did:example:subject"}
	cl := &claim.Claim{Issuer: "did:example:issuer", Subject: "did:example:subject", Value: "v"}
	att := &attestation.Attestation{Issuer: "did:example:issuer"}
	ev := &evidence.Evidence{Identifier: "urn:example:1"}

	cases := []struct {
		name string
		obj  TrustObject
		want func() ([32]byte, error)
	}{
		{"authority", NewAuthorityObject(auth), func() ([32]byte, error) { return authority.CanonicalHash(auth) }},
		{"claim", NewClaimObject(cl), func() ([32]byte, error) { return claim.CanonicalHash(cl) }},
		{"attestation", NewAttestationObject(att), func() ([32]byte, error) { return attestation.CanonicalHash(att) }},
		{"evidence", NewEvidenceObject(ev), func() ([32]byte, error) { return evidence.CanonicalHash(ev) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := tc.want()
			if err != nil {
				t.Fatalf("CanonicalHash() err = %v, want nil", err)
			}
			got, err := tc.obj.LeafHash()
			if err != nil {
				t.Fatalf("obj.LeafHash() err = %v, want nil", err)
			}
			if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				t.Errorf("obj.LeafHash() = %x, want %x", got, want)
			}
			free, err := LeafHash(tc.obj)
			if err != nil {
				t.Fatalf("LeafHash(obj) err = %v, want nil", err)
			}
			if subtle.ConstantTimeCompare(free[:], want[:]) != 1 {
				t.Errorf("LeafHash(obj) = %x, want %x", free, want)
			}
		})
	}
}

// TestLeafHash_FIPS1804 proves the SHA-256 primitive underlying every
// adapter's LeafHash path is FIPS-conformant. The adapters hash the
// [RFC 8785] JCS-canonical bytes of a struct, so the raw "abc" input
// cannot flow through an adapter unchanged — it is exercised at the
// crypto/hash layer that every CanonicalHash delegates to.
// Vector: [FIPS 180-4] "abc".
func TestLeafHash_FIPS1804(t *testing.T) {
	want, err := hex.DecodeString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	if err != nil {
		t.Fatalf("hex.DecodeString() err = %v, want nil", err)
	}
	got := hash.NewSHA256().Sum([]byte("abc"))
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		t.Errorf("SHA256(\"abc\") = %x, want %x", got, want)
	}
}

func TestLeafHash_NilInterface(t *testing.T) {
	_, err := LeafHash(nil)
	if !errors.Is(err, ErrNilObject) {
		t.Errorf("LeafHash(nil) err = %v, want ErrNilObject", err)
	}
}

func TestLeafHash_TypedNilAuthority(t *testing.T) {
	_, err := AuthorityObject{Authority: nil}.LeafHash()
	if !errors.Is(err, authority.ErrNilAuthority) {
		t.Errorf("AuthorityObject{nil}.LeafHash() err = %v, want ErrNilAuthority", err)
	}
	if _, err := LeafHash(AuthorityObject{Authority: nil}); !errors.Is(err, authority.ErrNilAuthority) {
		t.Errorf("LeafHash(AuthorityObject{nil}) err = %v, want ErrNilAuthority", err)
	}
}

func TestLeafHash_TypedNilEvidence(t *testing.T) {
	_, err := EvidenceObject{Evidence: nil}.LeafHash()
	if !errors.Is(err, evidence.ErrNilEvidence) {
		t.Errorf("EvidenceObject{nil}.LeafHash() err = %v, want ErrNilEvidence", err)
	}
	if _, err := LeafHash(EvidenceObject{Evidence: nil}); !errors.Is(err, evidence.ErrNilEvidence) {
		t.Errorf("LeafHash(EvidenceObject{nil}) err = %v, want ErrNilEvidence", err)
	}
}
