// Package rsa implements [RFC 8017] §8.1 (PSS) and §8.2 (PKCS1v1.5)
// RSA digital signatures. Provides key generation, signing, and
// verification using the Go stdlib crypto/rsa package.
//
// PSS (Probabilistic Signature Scheme) is the preferred scheme for
// new deployments — it is probabilistic, with a random salt per
// signature. PKCS1v1.5 is deterministic and required for JWKS/OIDC
// interop where providers sign with RS256/RS384/RS512.
//
// The wrapper enforces scheme separation at the type level: PSS and
// PKCS1v1.5 have separate exported key types, so the compiler prevents
// signing PSS with a PKCS1 key and vice versa. The hash function is
// bound at construction time, preventing hash downgrade attacks.
//
// Minimum key size is 2048 bits. PSS salt length is fixed to the hash
// output length per [RFC 8017] §8.1. Private keys expose Redact() for
// logging, never String()/Format()/GoString().
package rsa
