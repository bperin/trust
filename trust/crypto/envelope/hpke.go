package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/bperin/trust/crypto/hkdf"
	"github.com/bperin/trust/crypto/x25519"
)

// Errors returned by HPKE.
var (
	// ErrInvalidEnc is returned when the encapsulated key is not a valid X25519 public key.
	ErrInvalidEnc = errors.New("envelope: invalid encapsulated key")
	// ErrDecryptionFailed is returned when HPKE Open fails.
	ErrDecryptionFailed = errors.New("envelope: HPKE decryption failed")
	// ErrInvalidSuite is returned when the HPKE suite is not supported.
	ErrInvalidSuite = errors.New("envelope: unsupported HPKE suite")
)

// HPKE mode identifiers per [RFC 9180] §5.
const (
	modeBase = 0x00 // [RFC 9180] §5.1 base mode
)

// HPKE suite identifiers per [RFC 9180] §7.
const (
	kemX25519     = 0x0020 // [RFC 9180] §7.1
	kdfHKDFSHA256 = 0x0001 // [RFC 9180] §7.2
	aeadAES128GCM = 0x0001 // [RFC 9180] §7.3
)

// HPKE label prefix per [RFC 9180] §4.
const hpkeLabelPrefix = "HPKE-v1"

// Suite holds the HPKE cipher suite parameters per [RFC 9180] §7.
// Only X25519 + HKDF-SHA256 + AES-128-GCM is supported in this
// implementation.
type Suite struct {
	KEMID  uint16
	KDFID  uint16
	AEADID uint16
}

// DefaultSuite returns the default HPKE suite: X25519 + HKDF-SHA256 +
// AES-128-GCM per [RFC 9180] §7.
func DefaultSuite() Suite {
	return Suite{KEMID: kemX25519, KDFID: kdfHKDFSHA256, AEADID: aeadAES128GCM}
}

// Sender holds the HPKE sender state after [RFC 9180] §5.1 setup.
type Sender struct {
	suite   Suite
	aead    cipher.AEAD
	nonce   []byte // base nonce (12 bytes)
	counter uint64
}

// Receiver holds the HPKE receiver state after [RFC 9180] §5.2 setup.
type Receiver struct {
	suite   Suite
	aead    cipher.AEAD
	nonce   []byte // base nonce (12 bytes)
	counter uint64
}

// suiteID builds the HPKE suite ID per [RFC 9180] §7:
// "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
func suiteID(s Suite) []byte {
	b := make([]byte, 8)
	copy(b[:4], "HPKE")
	binary.BigEndian.PutUint16(b[4:6], s.KEMID)
	binary.BigEndian.PutUint16(b[6:8], s.AEADID)
	// Wait — suite_id is "HPKE" || kem(2) || kdf(2) || aead(2) = 10 bytes
	b = make([]byte, 10)
	copy(b[:4], "HPKE")
	binary.BigEndian.PutUint16(b[4:6], s.KEMID)
	binary.BigEndian.PutUint16(b[6:8], s.KDFID)
	binary.BigEndian.PutUint16(b[8:10], s.AEADID)
	return b
}

// labeledExtract implements [RFC 9180] §4 LabeledExtract:
// labeled_ikm = "HPKE-v1" || suite_id || label || ikm
// return Extract(salt, ikm=labeled_ikm)
func labeledExtract(s Suite, salt []byte, label string, ikm []byte) ([]byte, error) {
	sid := suiteID(s)
	labeled := make([]byte, 0, len(hpkeLabelPrefix)+len(sid)+len(label)+len(ikm))
	labeled = append(labeled, hpkeLabelPrefix...)
	labeled = append(labeled, sid...)
	labeled = append(labeled, label...)
	labeled = append(labeled, ikm...)
	return hkdf.Extract(labeled, salt)
}

// labeledExpand implements [RFC 9180] §4 LabeledExpand:
// labeled_info = I2OSP(length, 2) || "HPKE-v1" || suite_id || label || info
// return Expand(prk, labeled_info, length)
func labeledExpand(s Suite, prk []byte, label string, info []byte, length int) ([]byte, error) {
	sid := suiteID(s)
	labeled := make([]byte, 0, 2+len(hpkeLabelPrefix)+len(sid)+len(label)+len(info))
	labeled = append(labeled, byte(length>>8), byte(length))
	labeled = append(labeled, hpkeLabelPrefix...)
	labeled = append(labeled, sid...)
	labeled = append(labeled, label...)
	labeled = append(labeled, info...)
	return hkdf.Expand(prk, labeled, length)
}

// keySchedule derives the HPKE key and nonce using HKDF per
// [RFC 9180] §5.1. For base mode, psk and psk_id are empty.
func keySchedule(s Suite, sharedSecret, info []byte) (key, nonce []byte, err error) {
	// psk_id_hash = LabeledExtract(salt="", "psk_id_hash", "")
	pskIDHash, err := labeledExtract(s, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: HPKE psk_id_hash: %w", err)
	}
	// info_hash = LabeledExtract(salt="", "info_hash", info)
	infoHash, err := labeledExtract(s, nil, "info_hash", info)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: HPKE info_hash: %w", err)
	}
	// key_schedule_context = mode || psk_id_hash || info_hash
	ksContext := make([]byte, 0, 1+len(pskIDHash)+len(infoHash))
	ksContext = append(ksContext, modeBase)
	ksContext = append(ksContext, pskIDHash...)
	ksContext = append(ksContext, infoHash...)
	// secret = LabeledExtract(salt=shared_secret, "secret", ikm=psk)
	// For base mode, psk is empty.
	secret, err := labeledExtract(s, sharedSecret, "secret", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: HPKE secret: %w", err)
	}
	// key = LabeledExpand("key", key_schedule_context, Nk=16)
	key, err = labeledExpand(s, secret, "key", ksContext, 16)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: HPKE key: %w", err)
	}
	// nonce = LabeledExpand("base_nonce", key_schedule_context, Nn=12)
	nonce, err = labeledExpand(s, secret, "base_nonce", ksContext, 12)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: HPKE nonce: %w", err)
	}
	return key, nonce, nil
}

// newAEAD creates the AEAD cipher for the given suite and key.
func newAEAD(s Suite, key []byte) (cipher.AEAD, error) {
	switch s.AEADID {
	case aeadAES128GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("envelope: AES cipher creation failed: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("envelope: GCM mode creation failed: %w", err)
		}
		return gcm, nil
	default:
		return nil, fmt.Errorf("%w: AEAD ID 0x%04x", ErrInvalidSuite, s.AEADID)
	}
}

// nonceForCounter builds the nonce for the given counter per
// [RFC 9180] §5.3: base_nonce XOR I2OSP(counter, Nn).
func nonceForCounter(baseNonce []byte, counter uint64) []byte {
	nonce := make([]byte, len(baseNonce))
	copy(nonce, baseNonce)
	// XOR the counter into the last 8 bytes of the nonce
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-8+i] ^= byte(counter >> (uint(7-i) * 8))
	}
	return nonce
}

// SetupSender performs [RFC 9180] §5.1 base mode setup. Generates an
// ephemeral X25519 keypair, performs DH with the receiver's public
// key, and derives the key schedule using HKDF-SHA256. Returns the
// sender state and the encapsulated key (ephemeral public key).
func SetupSender(receiverPub *x25519.PublicKey, info []byte) (*Sender, []byte, error) {
	s := DefaultSuite()

	// Generate ephemeral X25519 keypair
	ephemeralPriv, ephemeralPub, err := x25519.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: HPKE ephemeral key generation: %w", err)
	}

	// DH with receiver public key → shared secret
	sharedSecret, err := ephemeralPriv.SharedSecret(receiverPub)
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: HPKE DH: %w", err)
	}

	// Key schedule
	key, nonce, err := keySchedule(s, sharedSecret, info)
	if err != nil {
		return nil, nil, err
	}

	// Create AEAD
	aead, err := newAEAD(s, key)
	if err != nil {
		return nil, nil, err
	}

	enc := ephemeralPub.Bytes()
	return &Sender{suite: s, aead: aead, nonce: nonce}, enc[:], nil
}

// SetupReceiver performs [RFC 9180] §5.2 base mode setup. Uses the
// receiver's private key to perform DH with the encapsulated key,
// then derives the key schedule using HKDF-SHA256. Returns the
// receiver state.
func SetupReceiver(enc []byte, receiverPriv *x25519.PrivateKey, info []byte) (*Receiver, error) {
	s := DefaultSuite()

	// Parse encapsulated key (ephemeral public key)
	if len(enc) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, want 32", ErrInvalidEnc, len(enc))
	}
	ephemeralPub, err := x25519.NewPublicKey(enc)
	if err != nil {
		return nil, fmt.Errorf("envelope: HPKE enc parsing: %w", err)
	}

	// DH with encapsulated key → shared secret
	sharedSecret, err := receiverPriv.SharedSecret(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("envelope: HPKE DH: %w", err)
	}

	// Key schedule
	key, nonce, err := keySchedule(s, sharedSecret, info)
	if err != nil {
		return nil, err
	}

	// Create AEAD
	aead, err := newAEAD(s, key)
	if err != nil {
		return nil, err
	}

	return &Receiver{suite: s, aead: aead, nonce: nonce}, nil
}

// Seal encrypts plaintext using the established HPKE key per
// [RFC 9180] §5.3. Increments the nonce counter. Returns the
// ciphertext (ciphertext || tag).
func (s *Sender) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := nonceForCounter(s.nonce, s.counter)
	s.counter++
	ciphertext := s.aead.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nil
}

// Open decrypts ciphertext using the established HPKE key per
// [RFC 9180] §5.3. Increments the nonce counter. Returns the
// plaintext, or ErrDecryptionFailed if decryption fails.
func (r *Receiver) Open(ciphertext, aad []byte) ([]byte, error) {
	nonce := nonceForCounter(r.nonce, r.counter)
	r.counter++
	plaintext, err := r.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	return plaintext, nil
}
