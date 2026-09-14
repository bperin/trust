// Package verification walks a trust path from an attestation to its
// root authority and produces two artifacts: a traversable provenance
// chain (Attestation → Claim → SigningKey → Authority → Delegation →
// RootAuthority → Identity) that survives serialization, and a
// structured verification Result naming each check and its failure.
//
// # Purity contract
//
// The engine is offline and pure: the caller supplies every public key
// and object through Inputs. The package performs no network or
// filesystem I/O, reads no global state beyond an injectable clock, and
// never takes custody of private key material — only crypto.PublicKey
// values cross the boundary.
//
// # Failure taxonomy
//
// Failures are sentinel errors declared in errors.go, distinguishable
// with errors.Is: signature mismatch, invalid authority, scope
// violation, expiry, and revocation each map to a distinct sentinel.
package verification
