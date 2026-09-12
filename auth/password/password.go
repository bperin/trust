package password

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidPassword is returned when a password fails verification —
// either the hash is malformed or the password does not match.
var ErrInvalidPassword = errors.New("password: invalid password")

// Hash produces a bcrypt hash of the given password using the default
// cost (bcrypt.DefaultCost). The returned string is safe to store in a
// database. Callers should treat the hash as opaque.
//
// Implements bcrypt per [NIST SP 800-132] §4.1 — a salted, adaptive
// password-based key derivation. The default cost (10) provides
// approximately 100ms of computation on 2024 hardware, which is the
// baseline for online threat models.
func Hash(password string) (string, error) {
	if len(password) == 0 {
		return "", ErrInvalidPassword
	}
	if len(password) > 72 {
		return "", ErrInvalidPassword
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// Verify checks a password against a previously computed bcrypt hash.
// Returns nil on success, ErrInvalidPassword on mismatch or malformed
// hash. The comparison is constant-time within bcrypt's internal
// implementation.
func Verify(hashedPassword, password string) error {
	if len(hashedPassword) == 0 || len(password) == 0 {
		return ErrInvalidPassword
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return ErrInvalidPassword
	}
	return nil
}
