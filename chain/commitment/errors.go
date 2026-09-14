package commitment

import "errors"

// Sentinel errors for the commitment package, checked with errors.Is.
// Constructing an anchor, publishing a root, and verifying a proof
// each fail with one of these sentinels wrapped by fmt.Errorf and %w.
var (
	// ErrNilAnchor is returned when an *Anchor receiver or argument is nil.
	ErrNilAnchor = errors.New("commitment: nil anchor")

	// ErrNilWallet is returned when a nil wallet is supplied for signing.
	ErrNilWallet = errors.New("commitment: nil wallet")

	// ErrInvalidAnchor is returned when an anchor's chain ID or contract address is invalid.
	ErrInvalidAnchor = errors.New("commitment: invalid anchor")

	// ErrMissingTxParams is returned when required transaction parameters are absent.
	ErrMissingTxParams = errors.New("commitment: missing transaction params")

	// ErrMalformedReceipt is returned when a transaction receipt is missing fields or has wrong types.
	ErrMalformedReceipt = errors.New("commitment: malformed receipt")

	// ErrChainIDMismatch is returned when a proof or receipt names a different chain than the anchor.
	ErrChainIDMismatch = errors.New("commitment: chain ID mismatch")

	// ErrNotConfirmed is returned when the anchoring transaction is not yet mined or failed.
	ErrNotConfirmed = errors.New("commitment: transaction not confirmed")

	// ErrRootMismatch is returned when the on-chain root differs from the expected Merkle root.
	ErrRootMismatch = errors.New("commitment: root mismatch")

	// ErrBadSignature is returned when a commitment proof signature fails verification.
	ErrBadSignature = errors.New("commitment: bad signature")

	// ErrRootGetterFailed is returned when the caller-supplied root getter cannot read the chain.
	ErrRootGetterFailed = errors.New("commitment: root getter failed")
)
