package verification

import "time"

// Option configures an Engine at construction.
type Option func(*Engine)

// NewEngine builds an immutable Engine; nil options are ignored.
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

// WithClock overrides the clock used when Inputs.Now is zero; nil is ignored.
func WithClock(clock func() time.Time) Option {
	return func(e *Engine) {
		if clock != nil {
			e.clock = clock
		}
	}
}

// WithKeyBinder overrides the default DocumentKeyBinder; nil is ignored.
func WithKeyBinder(binder KeyBinder) Option {
	return func(e *Engine) {
		if binder != nil {
			e.binder = binder
		}
	}
}

// WithCommitmentChecker configures commitment verification; nil default makes CheckCommitment skip.
func WithCommitmentChecker(checker CommitmentChecker) Option {
	return func(e *Engine) {
		e.commitmentChecker = checker
	}
}
