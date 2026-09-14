package kms

import (
	"errors"
	"fmt"

	"github.com/bperin/trust/crypto/secp256k1"
)

// ErrNoRecoveryID is returned by ComputeRecoveryID when none of the
// recovery ids 0–3 recover a public key matching the expected key.
var ErrNoRecoveryID = errors.New("kms: no recovery id matched the public key")

// ComputeRecoveryID computes the [SEC 1 v2] §4.3.3 recovery id for a
// 64-byte r||s signature over a 32-byte digest by trying recID 0, 1,
// 2, 3 via secp256k1.RecoverPubKey and comparing each recovered public
// key to pub (using the 33-byte compressed serialized form).
//
// KMS providers return r||s with no recovery id. The public key must
// be fetched and cached before signing so the recovery id can be
// computed here. This is the highest-risk component: a wrong recID
// produces a signature that recovers to the wrong key, so the
// comparison is exact (byte-identical compressed form).
//
// Returns the matching recID in [0, 3], or an error wrapping
// ErrNoRecoveryID if none of the four candidates match pub. A nil pub
// is rejected.
//
// Reference: [SEC 1 v2] §4.3.3 (public-key recovery from a signature).
func ComputeRecoveryID(sig, digest []byte, pub *secp256k1.PublicKey) (byte, error) {
	if pub == nil {
		return 0, fmt.Errorf("%w: nil public key", ErrNoRecoveryID)
	}
	// RecoverPubKey validates sig/digest length and recID range; let
	// those errors propagate directly so the caller sees the root
	// cause (e.g. a 64-byte sig requirement).
	for recID := byte(0); recID < 4; recID++ {
		recovered, err := secp256k1.RecoverPubKey(sig, digest, recID)
		if err != nil {
			continue
		}
		if recovered.Equal(pub) {
			return recID, nil
		}
	}
	return 0, fmt.Errorf("%w: tried recID 0-3, none matched", ErrNoRecoveryID)
}
