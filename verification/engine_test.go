package verification

import (
	"errors"
	"sync"
	"testing"
	"time"

	"crypto"

	"github.com/bperin/trust/identity/did"
)

func TestNewEngineDefaults(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	if _, ok := e.binder.(DocumentKeyBinder); !ok {
		t.Errorf("default binder = %T, want DocumentKeyBinder", e.binder)
	}
	if e.commitmentChecker != nil {
		t.Errorf("default commitment checker = %v, want nil", e.commitmentChecker)
	}
	if e.clock == nil {
		t.Error("default clock nil")
	}
	if len(e.checks) != 13 {
		t.Errorf("default checks = %d, want 13", len(e.checks))
	}
}

func TestWithClock(t *testing.T) {
	t.Parallel()
	calls := 0
	fixed := time.Now().Add(-time.Minute)
	e := NewEngine(WithClock(func() time.Time { calls++; return fixed }))
	f := buildFixture(t)
	in := f.inputs()
	in.Now = time.Time{}
	if _, err := e.Verify(in); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if calls == 0 {
		t.Error("injected clock never called for zero Inputs.Now")
	}
}

func TestWithClockNil(t *testing.T) {
	t.Parallel()
	e := NewEngine(WithClock(nil))
	if e.clock == nil {
		t.Error("WithClock(nil) must be ignored, not clear the clock")
	}
}

func TestInputsNowOverridesClock(t *testing.T) {
	t.Parallel()
	calls := 0
	e := NewEngine(WithClock(func() time.Time { calls++; return time.Now() }))
	f := buildFixture(t)
	in := f.inputs()
	in.Now = f.now
	if _, err := e.Verify(in); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if calls != 0 {
		t.Errorf("clock called %d times with non-zero Inputs.Now, want 0", calls)
	}
}

// spyBinder records Bind calls.
type spyBinder struct {
	calls []string
}

func (b *spyBinder) Bind(keyID string, doc *did.Document) (crypto.PublicKey, error) {
	b.calls = append(b.calls, keyID)
	return nil, errors.New("spy binder: not bound")
}

// countingChecker records Verify calls.
type countingChecker struct {
	calls int
}

func (c *countingChecker) Verify(proof CommitmentProof, in Inputs) error {
	c.calls++
	return nil
}

func TestWithKeyBinder(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	spy := &spyBinder{}
	e := NewEngine(WithKeyBinder(spy))
	in := f.inputs()
	if _, err := e.Verify(in); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(spy.calls) == 0 {
		t.Error("injected binder never invoked")
	}
}

func TestWithCommitmentChecker(t *testing.T) {
	t.Parallel()
	checker := &countingChecker{}
	e := NewEngine(WithCommitmentChecker(checker))
	if e.commitmentChecker != checker {
		t.Error("injected commitment checker not stored")
	}
	if NewEngine().commitmentChecker != nil {
		t.Error("default commitment checker not nil")
	}
}

func TestVerifyNilAttestation(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.Attestation = nil
	res, err := NewEngine().Verify(in)
	if !errors.Is(err, ErrNilAttestation) || res != nil {
		t.Errorf("res=%v err=%v, want nil result and ErrNilAttestation", res, err)
	}
}

func TestVerifyNilSigningKey(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.SigningKey = nil
	res, err := NewEngine().Verify(in)
	if !errors.Is(err, ErrNilSigningKey) {
		t.Errorf("err = %v, want ErrNilSigningKey", err)
	}
	if res != nil {
		t.Error("result should be nil on programmer error")
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.Chain = nil
	res, err := NewEngine().Verify(in)
	if !errors.Is(err, ErrEmptyChain) {
		t.Errorf("err = %v, want ErrEmptyChain", err)
	}
	if res != nil {
		t.Error("result should be nil on programmer error")
	}
}

func TestVerifyConcurrent(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	e := NewEngine()
	first, err := e.Verify(in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var wg sync.WaitGroup
	results := make([]*Result, 32)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := e.Verify(in)
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
				return
			}
			results[i] = res
		}(i)
	}
	wg.Wait()
	for i, res := range results {
		if res.Valid != first.Valid || len(res.Failures) != len(first.Failures) {
			t.Errorf("goroutine %d result diverged", i)
		}
		h1, _ := CanonicalHash(first.Provenance)
		h2, _ := CanonicalHash(res.Provenance)
		if hashRefHex(h1) != hashRefHex(h2) {
			t.Errorf("goroutine %d provenance digest differs", i)
		}
	}
}
