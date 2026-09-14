package claim

import (
	"errors"
	"testing"

	"github.com/bperin/trust/authority"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	good := testClaim()

	emptyIssuer := testClaim()
	emptyIssuer.Issuer = ""

	emptySubject := testClaim()
	emptySubject.Subject = ""

	emptyTypeNamespace := testClaim()
	emptyTypeNamespace.Type.Namespace = ""

	emptyTypeName := testClaim()
	emptyTypeName.Type.Name = ""

	nilValue := testClaim()
	nilValue.Value = nil

	unsortedScope := testClaim()
	unsortedScope.Scope.Resources = []string{"b", "a"}

	duplicateScope := testClaim()
	duplicateScope.Scope.Actions = []string{"read", "read"}

	cases := []struct {
		name    string
		claim   *Claim
		wantErr error
	}{
		{"valid claim", good, nil},
		{"nil claim", nil, ErrNilClaim},
		{"empty issuer", emptyIssuer, ErrEmptyIssuer},
		{"empty subject", emptySubject, ErrEmptySubject},
		{"empty claim type namespace", emptyTypeNamespace, ErrEmptyClaimTypeNamespace},
		{"empty claim type name", emptyTypeName, ErrEmptyClaimTypeName},
		{"nil value", nilValue, ErrNilValue},
		{"unsorted scope resources", unsortedScope, authority.ErrUnsortedScope},
		{"duplicate scope actions", duplicateScope, authority.ErrUnsortedScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(tc.claim)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate: got err %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidate_ScopeDelegationWrapsError(t *testing.T) {
	t.Parallel()

	c := testClaim()
	c.Scope.Resources = []string{"b", "a"}

	err := Validate(c)
	if err == nil {
		t.Fatal("Validate: got nil err, want wrapped authority.ErrUnsortedScope")
	}
	if !errors.Is(err, authority.ErrUnsortedScope) {
		t.Fatalf("Validate: got err %v, want wrapping %v", err, authority.ErrUnsortedScope)
	}
}
