package envelope

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/bperin/trust/crypto/x25519"
	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// Errors returned by HPKE.
var (
	// ErrInvalidEnc is returned when the encapsulated key is not a valid
	// X25519 public key (must be exactly 32 bytes).
	ErrInvalidEnc = errors.New("envelope: invalid encapsulated key")
	// ErrDecryptionFailed is returned when HPKE Open fails.
	ErrDecryptionFailed = errors.New("envelope: HPKE decryption failed")
	// ErrInvalidSuite is returned when the HPKE suite is not supported.
	ErrInvalidSuite = errors.New("envelope: unsupported HPKE suite")
)

// HPKE suite identifiers per [RFC 9180] §7. Only the X25519 + HKDF-SHA256
// + AES-128-GCM suite is supported.
const (
	kemX25519     = 0x0020
	kdfHKDFSHA256 = 0x0001
	aeadAES128GCM = 0x0001
)

// Suite holds the HPKE cipher suite parameters. Only X25519 +
// HKDF-SHA256 + AES-128-GCM is supported.
type Suite struct {
	KEMID  uint16
	KDFID  uint16
	AEADID uint16
}

// DefaultSuite returns the default HPKE suite: X25519 + HKDF-SHA256 +
// AES-128-GCM.
func DefaultSuite() Suite {
	return Suite{KEMID: kemX25519, KDFID: kdfHKDFSHA256, AEADID: aeadAES128GCM}
}

// Sender holds the HPKE sender state after setup. It wraps a circl
// hpke.Sealer; no circl types are exposed through the public API.
type Sender struct {
	sealer hpke.Sealer
}

// Receiver holds the HPKE receiver state after setup. It wraps a circl
// hpke.Opener; no circl types are exposed through the public API.
type Receiver struct {
	opener hpke.Opener
}

// circlSuite returns the circl HPKE suite matching DefaultSuite. The
// suite is constructed once per call; circl validates the combination
// internally.
func circlSuite() hpke.Suite {
	return hpke.NewSuite(
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_AES128GCM,
	)
}

// toKEMPublicKey converts a trust x25519.PublicKey to a circl
// kem.PublicKey. Both use the same 32-byte raw X25519 representation;
// no format conversion is needed.
func toKEMPublicKey(pub *x25519.PublicKey) (kem.PublicKey, error) {
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	raw := pub.Bytes()
	return scheme.UnmarshalBinaryPublicKey(raw[:])
}

// toKEMPrivateKey converts a trust x25519.PrivateKey to a circl
// kem.PrivateKey. Both use the same 32-byte raw X25519 representation;
// no format conversion is needed.
func toKEMPrivateKey(priv *x25519.PrivateKey) (kem.PrivateKey, error) {
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	raw := priv.Bytes()
	return scheme.UnmarshalBinaryPrivateKey(raw[:])
}

// SetupSender performs HPKE base mode setup per [RFC 9180] §5.1.
// Generates an ephemeral X25519 keypair, derives the key schedule, and
// returns the sender state along with the encapsulated key (32-byte
// ephemeral public key).
func SetupSender(receiverPub *x25519.PublicKey, info []byte) (*Sender, []byte, error) {
	pkR, err := toKEMPublicKey(receiverPub)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: HPKE recipient public key: %w", err)
	}

	suite := circlSuite()
	sender, err := suite.NewSender(pkR, info)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: HPKE NewSender: %w", err)
	}

	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: HPKE sender setup: %w", err)
	}

	return &Sender{sealer: sealer}, enc, nil
}

// SetupReceiver performs HPKE base mode setup per [RFC 9180] §5.2.
// Uses the receiver's private key to decapsulate the encapsulated key,
// then derives the key schedule. Returns the receiver state.
func SetupReceiver(enc []byte, receiverPriv *x25519.PrivateKey, info []byte) (*Receiver, error) {
	if len(enc) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, want 32", ErrInvalidEnc, len(enc))
	}

	skR, err := toKEMPrivateKey(receiverPriv)
	if err != nil {
		return nil, fmt.Errorf("envelope: HPKE recipient private key: %w", err)
	}

	suite := circlSuite()
	receiver, err := suite.NewReceiver(skR, info)
	if err != nil {
		return nil, fmt.Errorf("envelope: HPKE NewReceiver: %w", err)
	}

	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("envelope: HPKE receiver setup: %w", err)
	}

	return &Receiver{opener: opener}, nil
}

// Seal encrypts plaintext using the established HPKE key. The nonce is
// managed internally by circl. Returns ciphertext || tag.
func (s *Sender) Seal(plaintext, aad []byte) ([]byte, error) {
	return s.sealer.Seal(plaintext, aad)
}

// Open decrypts ciphertext using the established HPKE key. The nonce
// is managed internally by circl. Returns ErrDecryptionFailed if
// decryption fails.
func (r *Receiver) Open(ciphertext, aad []byte) ([]byte, error) {
	pt, err := r.opener.Open(ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	return pt, nil
}
