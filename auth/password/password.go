package password

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidPassword is returned when a password fails verification,
// either because the hash is malformed or the password does not match.
var ErrInvalidPassword = errors.New("password: invalid password")

// Hash returns a bcrypt hash of password using bcrypt.DefaultCost.
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

// Verify reports whether password matches the bcrypt hash, returning
// ErrInvalidPassword on mismatch or malformed hash.
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
