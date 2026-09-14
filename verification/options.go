package verification

import "time"

// Option configures an Engine at construction.
type Option func(*Engine)

// NewEngine builds an immutable Engine: default clock time.Now, default
// binder DocumentKeyBinder{}, no commitment checker, and the fixed
// default check pipeline. Options are applied over the defaults; nil
// options are ignored.
func NewEngine(opts ...Option) *Engine {
	e := &Engine{
		clock:  time.Now,
		binder: DocumentKeyBinder{},
		checks: defaultChecks(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	return e
}

// WithClock overrides the engine clock used when Inputs.Now is zero.
// A nil clock is ignored.
func WithClock(clock func() time.Time) Option {
	return func(e *Engine) {
		if clock != nil {
			e.clock = clock
		}
	}
}

// WithKeyBinder overrides the default DocumentKeyBinder. A nil binder
// is ignored.
func WithKeyBinder(binder KeyBinder) Option {
	return func(e *Engine) {
		if binder != nil {
			e.binder = binder
		}
	}
}

// WithCommitmentChecker configures external commitment verification.
// The default is nil, which makes CheckCommitment skip.
func WithCommitmentChecker(checker CommitmentChecker) Option {
	return func(e *Engine) {
		e.commitmentChecker = checker
	}
}
