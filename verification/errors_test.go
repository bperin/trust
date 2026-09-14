package verification

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

var trustSentinels = []struct {
	name string
	err  error
}{
	{"ErrSignatureMismatch", ErrSignatureMismatch},
	{"ErrSignatureKeyMismatch", ErrSignatureKeyMismatch},
	{"ErrAuthorityInvalid", ErrAuthorityInvalid},
	{"ErrChainBroken", ErrChainBroken},
	{"ErrNotRootAuthority", ErrNotRootAuthority},
	{"ErrDelegationDepth", ErrDelegationDepth},
	{"ErrCapabilityNotGranted", ErrCapabilityNotGranted},
	{"ErrScopeViolation", ErrScopeViolation},
	{"ErrNotYetValid", ErrNotYetValid},
	{"ErrExpired", ErrExpired},
	{"ErrRevoked", ErrRevoked},
	{"ErrSuperseded", ErrSuperseded},
	{"ErrIdentityUnresolved", ErrIdentityUnresolved},
	{"ErrKeyBinding", ErrKeyBinding},
	{"ErrEvidenceIntegrity", ErrEvidenceIntegrity},
	{"ErrProvenanceMismatch", ErrProvenanceMismatch},
	{"ErrCommitmentInvalid", ErrCommitmentInvalid},
	{"ErrStructural", ErrStructural},
}

var programmerSentinels = []struct {
	name string
	err  error
}{
	{"ErrNilAttestation", ErrNilAttestation},
	{"ErrNilSigningKey", ErrNilSigningKey},
	{"ErrEmptyChain", ErrEmptyChain},
	{"ErrNilProvenance", ErrNilProvenance},
}

func allSentinels() []struct {
	name string
	err  error
} {
	all := make([]struct {
		name string
		err  error
	}, 0, len(trustSentinels)+len(programmerSentinels))
	all = append(all, trustSentinels...)
	all = append(all, programmerSentinels...)
	return all
}

func TestFailureSentinelsNeverAlias(t *testing.T) {
	for i, a := range trustSentinels {
		for j, b := range trustSentinels {
			if i == j {
				continue
			}
			if errors.Is(a.err, b.err) {
				t.Errorf("errors.Is(%s, %s) = true, want false: trust sentinels must not alias", a.name, b.name)
			}
			if errors.Is(b.err, a.err) {
				t.Errorf("errors.Is(%s, %s) = true, want false: trust sentinels must not alias", b.name, a.name)
			}
		}
	}
}

func TestProgrammerSentinelsNeverAlias(t *testing.T) {
	all := allSentinels()
	for _, p := range programmerSentinels {
		for _, s := range all {
			if s.name == p.name {
				continue
			}
			if errors.Is(p.err, s.err) {
				t.Errorf("errors.Is(%s, %s) = true, want false: programmer sentinel must be distinct", p.name, s.name)
			}
			if errors.Is(s.err, p.err) {
				t.Errorf("errors.Is(%s, %s) = true, want false: programmer sentinel must be distinct", s.name, p.name)
			}
		}
	}
}

func TestSentinelWrapping(t *testing.T) {
	tests := []struct {
		name    string
		wrapped error
		target  error
		want    bool
	}{
		{"hop-wrapped expired", fmt.Errorf("hop %d: %w", 2, ErrExpired), ErrExpired, true},
		{"hop-wrapped expired vs revoked", fmt.Errorf("hop %d: %w", 2, ErrExpired), ErrRevoked, false},
		{"context-wrapped scope violation", fmt.Errorf("check %s: %w", CheckChainLink, ErrScopeViolation), ErrScopeViolation, true},
		{"bare sentinel", ErrSignatureMismatch, ErrSignatureMismatch, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errors.Is(tt.wrapped, tt.target); got != tt.want {
				t.Errorf("errors.Is(%v, %v) = %v, want %v", tt.wrapped, tt.target, got, tt.want)
			}
		})
	}
}

func TestSentinelMessagesPrefixed(t *testing.T) {
	for _, s := range allSentinels() {
		t.Run(s.name, func(t *testing.T) {
			msg := s.err.Error()
			if !strings.HasPrefix(msg, "verification: ") {
				t.Errorf("%s message %q lacks %q prefix", s.name, msg, "verification: ")
			}
		})
	}
}

func TestSentinelMessagesUnique(t *testing.T) {
	seen := make(map[string]string, len(allSentinels()))
	for _, s := range allSentinels() {
		if prev, dup := seen[s.err.Error()]; dup {
			t.Errorf("%s shares message %q with %s, want unique", s.name, s.err.Error(), prev)
		}
		seen[s.err.Error()] = s.name
	}
}
