package evidence

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by ValidateEvidence. Check them with
// errors.Is.
var (
	// ErrEmptyIdentifier is returned by ValidateEvidence when
	// Evidence.Identifier is empty — an evidence reference must name
	// what it refers to.
	ErrEmptyIdentifier = errors.New("evidence: empty identifier")

	// ErrNilContentHash is returned by ValidateEvidence when
	// Evidence.ContentHash is nil — the reference must bind to a digest
	// of the material.
	ErrNilContentHash = errors.New("evidence: nil content hash")

	// ErrEmptyContentHash is returned by ValidateEvidence when
	// Evidence.ContentHash is a non-nil but zero-length slice.
	ErrEmptyContentHash = errors.New("evidence: empty content hash")

	// ErrContentHashLength is returned by ValidateEvidence when
	// Evidence.ContentHash is neither nil nor empty but its length is
	// not ContentHashLen — the [FIPS 180-4] SHA-256 digest size.
	ErrContentHashLength = errors.New("evidence: content hash length is not 32 bytes")

	// ErrEmptyMediaType is returned by ValidateEvidence when
	// Evidence.MediaType is empty — a consumer cannot interpret the
	// material without it.
	ErrEmptyMediaType = errors.New("evidence: empty media type")

	// ErrEmptyLocator is returned by ValidateEvidence when
	// Evidence.Locator is empty — the reference must say where the
	// material may be retrieved.
	ErrEmptyLocator = errors.New("evidence: empty locator")
)

// ValidateEvidence checks an evidence reference for structural validity:
// non-nil, with a non-empty Identifier, a ContentHash of exactly
// ContentHashLen bytes, and non-empty MediaType and Locator.
//
// Validation is structural only: it performs no temporal checks, no
// network access, and no content fetch — Locator is never dereferenced
// and ContentHash is never recomputed against the material.
func ValidateEvidence(ev *Evidence) error {
	if ev == nil {
		return ErrNilEvidence
	}
	if ev.Identifier == "" {
		return ErrEmptyIdentifier
	}
	if ev.ContentHash == nil {
		return ErrNilContentHash
	}
	if len(ev.ContentHash) == 0 {
		return ErrEmptyContentHash
	}
	if len(ev.ContentHash) != ContentHashLen {
		return fmt.Errorf("%w: got %d bytes", ErrContentHashLength, len(ev.ContentHash))
	}
	if ev.MediaType == "" {
		return ErrEmptyMediaType
	}
	if ev.Locator == "" {
		return ErrEmptyLocator
	}
	return nil
}
