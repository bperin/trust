// Package der parses ASN.1 DER-encoded ECDSA signatures and normalizes
// the s value to low-s per [EIP-2].
//
// AWS KMS and GCP KMS return DER-encoded ECDSA-Sig-Value per [SEC 1 v2]
// §2.3.3 and [RFC 3279] §2.2.3. The DER encoding must be parsed to raw
// r||s before it can be used by the secp256k1 signing/recovery path.
package der

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// ErrInvalidDER is returned when a DER-encoded ECDSA signature is
// malformed or does not match the ECDSA-Sig-Value structure.
var ErrInvalidDER = errors.New("der: invalid ECDSA signature")

// ecdsaSigValue is the ECDSA-Sig-Value structure per [SEC 1 v2] §2.3.3.
type ecdsaSigValue struct {
	R, S *big.Int
}

// ParseECDSASignature parses an ASN.1 DER-encoded ECDSA-Sig-Value per
// [SEC 1 v2] §2.3.3 into raw r and s byte slices.
//
// Scalars are validated to be in [1, n-1] where n is the secp256k1
// curve order. Zero, negative, oversized, and out-of-range scalars are
// rejected. Malformed DER is rejected with an error wrapping
// ErrInvalidDER.
func ParseECDSASignature(derBytes []byte) (r, s []byte, err error) {
	if len(derBytes) == 0 {
		return nil, nil, fmt.Errorf("%w: empty input", ErrInvalidDER)
	}

	var sig ecdsaSigValue
	rest, err := asn1.Unmarshal(derBytes, &sig)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: asn1 parse failed: %v", ErrInvalidDER, err)
	}
	if len(rest) != 0 {
		return nil, nil, fmt.Errorf("%w: trailing bytes after ECDSA-Sig-Value (%d)", ErrInvalidDER, len(rest))
	}
	if sig.R == nil || sig.S == nil {
		return nil, nil, fmt.Errorf("%w: missing r or s", ErrInvalidDER)
	}
	if sig.R.Sign() < 0 || sig.S.Sign() < 0 {
		return nil, nil, fmt.Errorf("%w: negative integer", ErrInvalidDER)
	}
	if sig.R.Sign() == 0 || sig.S.Sign() == 0 {
		return nil, nil, fmt.Errorf("%w: zero integer", ErrInvalidDER)
	}
	// [SEC 1 v2] §2.2.1 — r and s must lie in [1, n-1]. Rejects both
	// oversized scalars (bit length > 256) and in-width scalars that
	// are still >= the secp256k1 curve order n.
	if sig.R.Cmp(secp256k1N) >= 0 || sig.S.Cmp(secp256k1N) >= 0 {
		return nil, nil, fmt.Errorf("%w: scalar out of range [1, n-1]", ErrInvalidDER)
	}

	r = sig.R.Bytes()
	s = sig.S.Bytes()
	return r, s, nil
}

// secp256k1N is the curve order n for secp256k1 per [SEC 2 v2].
var secp256k1N = func() *big.Int {
	n, ok := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	if !ok {
		panic("der: invalid secp256k1 curve order constant")
	}
	return n
}()

// secp256k1HalfN is n/2, the threshold above which s is high and must
// be normalized to low-s per [EIP-2].
var secp256k1HalfN = func() *big.Int {
	return new(big.Int).Rsh(secp256k1N, 1)
}()

// NormalizeLowS normalizes s to low-s per [EIP-2]. If s > n/2, s is
// replaced with n - s and flipped is set to true. The caller uses
// flipped to adjust the recovery id: flipping s inverts the recovery
// id by XOR 1.
func NormalizeLowS(s []byte) (normalized []byte, flipped bool) {
	sInt := new(big.Int).SetBytes(s)

	// If s > n/2, normalize to n - s.
	if sInt.Cmp(secp256k1HalfN) > 0 {
		normalizedInt := new(big.Int).Sub(secp256k1N, sInt)
		return normalizedInt.Bytes(), true
	}
	// Already low-s; return a copy so the caller may mutate freely.
	out := make([]byte, len(s))
	copy(out, s)
	return out, false
}
