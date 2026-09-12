package password

import (
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "correct-horse-battery-staple",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  true,
		},
		{
			name:     "password at 72-byte limit",
			password: strings.Repeat("a", 72),
			wantErr:  false,
		},
		{
			name:     "password over 72-byte limit",
			password: strings.Repeat("a", 73),
			wantErr:  true,
		},
		{
			name:     "single character",
			password: "x",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hash, err := Hash(tt.password)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Hash(%q) expected error, got nil", tt.password)
				}
				if err != ErrInvalidPassword {
					t.Fatalf("Hash(%q) expected ErrInvalidPassword, got %v", tt.password, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Hash(%q) unexpected error: %v", tt.password, err)
			}
			if hash == "" {
				t.Fatal("Hash returned empty string")
			}
			if !strings.HasPrefix(hash, "$2a$") {
				t.Fatalf("Hash returned non-bcrypt prefix: %s", hash[:min(len(hash), 4)])
			}
		})
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	validPassword := "correct-horse-battery-staple"
	validHash, err := Hash(validPassword)
	if err != nil {
		t.Fatalf("failed to hash test password: %v", err)
	}

	tests := []struct {
		name           string
		hashedPassword string
		password       string
		wantErr        bool
	}{
		{
			name:           "correct password",
			hashedPassword: validHash,
			password:       validPassword,
			wantErr:        false,
		},
		{
			name:           "wrong password",
			hashedPassword: validHash,
			password:       "wrong-password",
			wantErr:        true,
		},
		{
			name:           "empty password",
			hashedPassword: validHash,
			password:       "",
			wantErr:        true,
		},
		{
			name:           "empty hash",
			hashedPassword: "",
			password:       validPassword,
			wantErr:        true,
		},
		{
			name:           "malformed hash",
			hashedPassword: "not-a-bcrypt-hash",
			password:       validPassword,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := Verify(tt.hashedPassword, tt.password)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Verify expected error, got nil")
				}
				if err != ErrInvalidPassword {
					t.Fatalf("Verify expected ErrInvalidPassword, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify unexpected error: %v", err)
			}
		})
	}
}

func TestHashRoundTrip(t *testing.T) {
	t.Parallel()

	passwords := []string{
		"simple",
		"complex!P@ssw0rd#123",
		strings.Repeat("a", 72),
	}

	for _, pw := range passwords {
		t.Run(pw[:min(len(pw), 10)], func(t *testing.T) {
			t.Parallel()

			hash, err := Hash(pw)
			if err != nil {
				t.Fatalf("Hash failed: %v", err)
			}
			if err := Verify(hash, pw); err != nil {
				t.Fatalf("Verify failed: %v", err)
			}
		})
	}
}

func TestHashUniqueness(t *testing.T) {
	t.Parallel()

	pw := "same-password"
	hashes := make(map[string]bool)
	for i := 0; i < 10; i++ {
		hash, err := Hash(pw)
		if err != nil {
			t.Fatalf("Hash failed on iteration %d: %v", i, err)
		}
		if hashes[hash] {
			t.Fatalf("duplicate hash on iteration %d — salt not random", i)
		}
		hashes[hash] = true
	}
}
