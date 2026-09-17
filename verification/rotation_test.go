package verification

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bperin/trust/authority"
)

// rotationHistory returns the version-1 binding and version-2 rotation instants
// inside a fixture's validity window.
func rotationHistory(now time.Time) (bound, rotated time.Time) {
	return now.Add(-50 * time.Minute), now.Add(-10 * time.Minute)
}

// runKeyBindingWith runs CheckKeyBinding with a signing-key version history.
func runKeyBindingWith(t *testing.T, f *fixture, versions []KeyVersion, now time.Time) error {
	t.Helper()
	in := f.inputs()
	in.KeyVersions = versions
	in.Now = now
	prov, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	return checkKeyBinding(&checkContext{in: in, now: now, prov: prov, e: NewEngine(), hop: -1})
}

// TestRotation_KeyVersionSuperseded verifies the engine accepts a signature
// made under the version bound at the evaluation instant and names the
// superseded version once the identity has rotated.
func TestRotation_KeyVersionSuperseded(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		keyVersion uint64
		history    func(now time.Time) []KeyVersion
		evalAt     func(now time.Time) time.Time
		wantErr    error
		details    []string
	}{
		{
			name:       "current version, no rotation recorded",
			keyVersion: 1,
			history: func(now time.Time) []KeyVersion {
				bound, _ := rotationHistory(now)
				return []KeyVersion{{Version: 1, BoundAt: bound}}
			},
			evalAt: func(now time.Time) time.Time { return now },
		},
		{
			name:       "version 1 evaluated just before the rotation",
			keyVersion: 1,
			history:    rotationTwoVersions,
			evalAt:     func(now time.Time) time.Time { _, r := rotationHistory(now); return r.Add(-time.Nanosecond) },
		},
		{
			name:       "version 1 evaluated exactly at the rotation",
			keyVersion: 1,
			history:    rotationTwoVersions,
			evalAt:     func(now time.Time) time.Time { _, r := rotationHistory(now); return r },
			wantErr:    ErrKeyVersionSuperseded,
			details:    []string{"version 1", "version 2"},
		},
		{
			name:       "version 1 evaluated after the rotation",
			keyVersion: 1,
			history:    rotationTwoVersions,
			evalAt:     func(now time.Time) time.Time { return now },
			wantErr:    ErrKeyVersionSuperseded,
			details:    []string{"version 1 superseded by version 2"},
		},
		{
			name:       "version 2 evaluated after the rotation",
			keyVersion: 2,
			history:    rotationTwoVersions,
			evalAt:     func(now time.Time) time.Time { return now },
		},
		{
			name:       "version 0 evaluated against current version 1",
			keyVersion: 0,
			history: func(now time.Time) []KeyVersion {
				bound, _ := rotationHistory(now)
				return []KeyVersion{{Version: 1, BoundAt: bound}}
			},
			evalAt:  func(now time.Time) time.Time { return now },
			wantErr: ErrKeyVersionSuperseded,
			details: []string{"version 0 superseded by version 1"},
		},
		{
			name:       "no history recorded",
			keyVersion: 1,
			history:    func(time.Time) []KeyVersion { return nil },
			evalAt:     func(now time.Time) time.Time { return now },
		},
		{
			name:       "version revoked at the revocation instant",
			keyVersion: 1,
			history: func(now time.Time) []KeyVersion {
				bound, _ := rotationHistory(now)
				return []KeyVersion{{Version: 1, BoundAt: bound, RevokedAt: now}}
			},
			evalAt:  func(now time.Time) time.Time { return now },
			wantErr: ErrRevoked,
			details: []string{"version 1 revoked"},
		},
		{
			name:       "version revoked before the revocation instant",
			keyVersion: 1,
			history: func(now time.Time) []KeyVersion {
				bound, _ := rotationHistory(now)
				return []KeyVersion{{Version: 1, BoundAt: bound, RevokedAt: now.Add(time.Minute)}}
			},
			evalAt: func(now time.Time) time.Time { return now },
		},
		{
			name:       "history bound after the evaluation instant",
			keyVersion: 1,
			history: func(now time.Time) []KeyVersion {
				return []KeyVersion{{Version: 1, BoundAt: now.Add(time.Hour)}}
			},
			evalAt:  func(now time.Time) time.Time { return now },
			wantErr: ErrKeyBinding,
			details: []string{"no signing key version bound"},
		},
		{
			name:       "attestation version ahead of the bound version",
			keyVersion: 3,
			history: func(now time.Time) []KeyVersion {
				bound, rotated := rotationHistory(now)
				return []KeyVersion{{Version: 1, BoundAt: bound}, {Version: 2, BoundAt: rotated}}
			},
			evalAt:  func(now time.Time) time.Time { return now },
			wantErr: ErrKeyBinding,
			details: []string{"version 3 is not bound"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := buildFixture(t)
			f.att.SigningKeyVersion = tc.keyVersion
			f.resignAttestation(t)
			in := f.inputs()
			in.Now = tc.evalAt(f.now)
			in.KeyVersions = tc.history(f.now)

			res, err := NewEngine().Verify(in)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.Valid != (len(res.Failures) == 0) {
				t.Fatalf("Valid=%v with %d failures, want the invariant to hold", res.Valid, len(res.Failures))
			}
			if tc.wantErr == nil {
				if !res.Valid {
					for _, fl := range res.Failures {
						t.Errorf("failure: check=%v err=%v", fl.Check, fl.Err)
					}
					t.Fatalf("result invalid, want valid")
				}
				return
			}
			if res.Valid {
				t.Fatalf("result valid, want %v", tc.wantErr)
			}
			var found *Failure
			for i := range res.Failures {
				if res.Failures[i].Check == CheckKeyBinding {
					found = &res.Failures[i]
				}
			}
			if found == nil {
				t.Fatalf("failures = %v, want one at %v", res.Failures, CheckKeyBinding)
			}
			if !errors.Is(found.Err, tc.wantErr) {
				t.Errorf("errors.Is(err, %v) = false for err %v, want true", tc.wantErr, found.Err)
			}
			if found.Check != CheckKeyBinding {
				t.Errorf("failure check = %v, want %v", found.Check, CheckKeyBinding)
			}
			for _, want := range tc.details {
				if !strings.Contains(found.Detail, want) {
					t.Errorf("Detail = %q, want it to contain %q", found.Detail, want)
				}
			}
		})
	}
}

// rotationTwoVersions records a version 1→2 rotation one hour before now.
func rotationTwoVersions(now time.Time) []KeyVersion {
	bound, rotated := rotationHistory(now)
	return []KeyVersion{{Version: 1, BoundAt: bound}, {Version: 2, BoundAt: rotated}}
}

// TestRotation_ReissuedUnderNewVersion verifies an attestation re-signed under
// the rotated version passes the whole pipeline.
func TestRotation_ReissuedUnderNewVersion(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.att.SigningKeyVersion = 2
	f.resignAttestation(t)
	in := f.inputs()
	in.KeyVersions = rotationTwoVersions(f.now)

	res, err := NewEngine().Verify(in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid {
		for _, fl := range res.Failures {
			t.Errorf("failure: check=%v err=%v", fl.Check, fl.Err)
		}
		t.Fatal("version-2 attestation evaluated after the rotation reported invalid")
	}
}

// TestRotation_UnresignedVersionBumpIsSignatureFailure verifies that raising
// the version without re-signing fails as a signature problem, not as rotation.
func TestRotation_UnresignedVersionBumpIsSignatureFailure(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.att.SigningKeyVersion = 2
	in := f.inputs()
	in.KeyVersions = rotationTwoVersions(f.now)

	res, err := NewEngine().Verify(in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid {
		t.Fatal("result valid, want a signature failure")
	}
	first := res.Failures[0]
	if !errors.Is(first.Err, ErrSignatureMismatch) {
		t.Errorf("err = %v, want ErrSignatureMismatch", first.Err)
	}
	if errors.Is(first.Err, ErrKeyVersionSuperseded) {
		t.Errorf("err = %v, want it not to name a superseded key version", first.Err)
	}
	if status := checkStatus(res, CheckKeyBinding); status != CheckSkipped {
		t.Errorf("CheckKeyBinding status = %v, want %v", status, CheckSkipped)
	}
}

// TestRotation_SupersededVersionIsNotASignatureFailure verifies a superseded
// version fails at CheckKeyBinding while its signature still verifies.
func TestRotation_SupersededVersionIsNotASignatureFailure(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.KeyVersions = rotationTwoVersions(f.now)

	res, err := NewEngine().Verify(in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid {
		t.Fatal("result valid, want a superseded key version failure")
	}
	if status := checkStatus(res, CheckSignature); status != CheckPassed {
		t.Errorf("CheckSignature status = %v, want %v", status, CheckPassed)
	}
	if status := checkStatus(res, CheckKeyBinding); status != CheckFailed {
		t.Errorf("CheckKeyBinding status = %v, want %v", status, CheckFailed)
	}
	for _, fl := range res.Failures {
		if errors.Is(fl.Err, ErrSignatureMismatch) || errors.Is(fl.Err, ErrSignatureKeyMismatch) {
			t.Errorf("failure at %v = %v, want no signature failure", fl.Check, fl.Err)
		}
	}
}

// TestRotation_SupersededKeySentinelIsDistinct verifies the new sentinel names
// key rotation alone and is distinguishable from every adjacent failure.
func TestRotation_SupersededKeySentinelIsDistinct(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want error
	}{
		{"authority supersession", ErrSuperseded},
		{"revocation", ErrRevoked},
		{"expiry", ErrExpired},
		{"not yet valid", ErrNotYetValid},
		{"signature mismatch", ErrSignatureMismatch},
		{"signing key mismatch", ErrSignatureKeyMismatch},
		{"key binding mismatch", ErrKeyBinding},
		{"structural", ErrStructural},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if ErrKeyVersionSuperseded == tc.want {
				t.Fatalf("%v aliases the key-version sentinel", tc.name)
			}
			if errors.Is(ErrKeyVersionSuperseded, tc.want) {
				t.Errorf("errors.Is(ErrKeyVersionSuperseded, %v) = true, want false", tc.want)
			}
			if errors.Is(tc.want, ErrKeyVersionSuperseded) {
				t.Errorf("errors.Is(%v, ErrKeyVersionSuperseded) = true, want false", tc.want)
			}
		})
	}

	f := buildFixture(t)
	err := runKeyBindingWith(t, f, rotationTwoVersions(f.now), f.now)
	if err == nil {
		t.Fatal("checkKeyBinding passed, want a superseded key version failure")
	}
	for _, tc := range cases {
		if errors.Is(err, tc.want) {
			t.Errorf("superseded-version error %v matches %v, want only the key-version sentinel", err, tc.want)
		}
	}
	if !errors.Is(err, ErrKeyVersionSuperseded) {
		t.Errorf("errors.Is(err, ErrKeyVersionSuperseded) = false for err %v, want true", err)
	}

	// An authority superseded at a hop reports ErrSuperseded, not the key sentinel.
	superseded := buildFixture(t)
	superseded.chain[1].Authority.Status = authority.StatusSuperseded
	ctx, err := runSingleCheck(t, superseded, checkRevocation)
	if err == nil {
		t.Fatal("checkRevocation passed, want ErrSuperseded")
	}
	if !errors.Is(err, ErrSuperseded) {
		t.Errorf("err = %v, want ErrSuperseded", err)
	}
	if errors.Is(err, ErrKeyVersionSuperseded) {
		t.Errorf("err = %v (hop %d), want it not to name a superseded key version", err, ctx.hop)
	}
}

// TestRotation_SupersededVersionPerAlgorithm verifies the version check for a
// fixture of every registered algorithm.
func TestRotation_SupersededVersionPerAlgorithm(t *testing.T) {
	t.Parallel()
	for _, alg := range everyAlgorithm {
		alg := alg
		t.Run(alg.JOSE(), func(t *testing.T) {
			t.Parallel()
			f := buildFixtureAlg(t, alg)
			err := runKeyBindingWith(t, f, rotationTwoVersions(f.now), f.now)
			if !errors.Is(err, ErrKeyVersionSuperseded) {
				t.Errorf("err = %v, want ErrKeyVersionSuperseded", err)
			}
			if err != nil && !strings.Contains(err.Error(), "version 1 superseded by version 2") {
				t.Errorf("err = %v, want it to name both versions", err)
			}
		})
	}
}

// TestRotation_KeyVersionAtBoundary pins the in-effect selection: the highest
// BoundAt at or before the instant, ties broken toward the higher version.
func TestRotation_KeyVersionAtBoundary(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second).UTC()
	at := func(d time.Duration) time.Time { return now.Add(d) }
	cases := []struct {
		name    string
		history []KeyVersion
		want    uint64
		found   bool
	}{
		{"single bound entry", []KeyVersion{{Version: 1, BoundAt: at(-time.Hour)}}, 1, true},
		{"later entry wins", []KeyVersion{{Version: 1, BoundAt: at(-time.Hour)}, {Version: 2, BoundAt: at(-time.Minute)}}, 2, true},
		{"unsorted history still selects the latest", []KeyVersion{{Version: 3, BoundAt: at(-time.Minute)}, {Version: 1, BoundAt: at(-time.Hour)}}, 3, true},
		{"tie breaks toward the higher version", []KeyVersion{{Version: 4, BoundAt: at(-time.Minute)}, {Version: 5, BoundAt: at(-time.Minute)}}, 5, true},
		{"entry bound in the future is ignored", []KeyVersion{{Version: 1, BoundAt: at(-time.Hour)}, {Version: 2, BoundAt: at(time.Hour)}}, 1, true},
		{"entry bound exactly now is current", []KeyVersion{{Version: 2, BoundAt: now}}, 2, true},
		{"empty history", nil, 0, false},
		{"nothing bound yet", []KeyVersion{{Version: 1, BoundAt: at(time.Hour)}}, 0, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, found := keyVersionAt(tc.history, now)
			if found != tc.found {
				t.Fatalf("found = %v, want %v", found, tc.found)
			}
			if found && got.Version != tc.want {
				t.Errorf("version = %d, want %d", got.Version, tc.want)
			}
		})
	}
}

// checkStatus returns the recorded status of one check, or 0 when absent.
func checkStatus(res *Result, id CheckID) CheckStatus {
	for _, c := range res.Checks {
		if c.ID == id {
			return c.Status
		}
	}
	return 0
}
