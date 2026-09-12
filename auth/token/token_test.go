package token

import (
	"testing"
)

func TestGenerate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		nBytes  int
		wantErr bool
		wantLen int
	}{
		{
			name:    "default 32 bytes",
			nBytes:  DefaultBytes,
			wantErr: false,
			wantLen: 64, // 32 bytes hex-encoded = 64 chars
		},
		{
			name:    "16 bytes",
			nBytes:  16,
			wantErr: false,
			wantLen: 32,
		},
		{
			name:    "zero bytes",
			nBytes:  0,
			wantErr: false,
			wantLen: 0,
		},
		{
			name:    "negative bytes",
			nBytes:  -1,
			wantErr: true,
		},
		{
			name:    "1 byte",
			nBytes:  1,
			wantErr: false,
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token, err := Generate(tt.nBytes)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Generate(%d) expected error, got nil", tt.nBytes)
				}
				return
			}
			if err != nil {
				t.Fatalf("Generate(%d) unexpected error: %v", tt.nBytes, err)
			}
			if len(token) != tt.wantLen {
				t.Fatalf("Generate(%d) length = %d, want %d", tt.nBytes, len(token), tt.wantLen)
			}
		})
	}
}

func TestGenerateUniqueness(t *testing.T) {
	t.Parallel()

	tokens := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		token, err := Generate(DefaultBytes)
		if err != nil {
			t.Fatalf("Generate failed on iteration %d: %v", i, err)
		}
		if tokens[token] {
			t.Fatalf("duplicate token on iteration %d — CSPRNG not random", i)
		}
		tokens[token] = true
	}
}

func TestHashForStorage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "standard token",
			token: "abc123def456",
		},
		{
			name:  "empty string",
			token: "",
		},
		{
			name:  "long token",
			token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hash := HashForStorage(tt.token)

			// SHA-256 hex is always 64 chars
			if len(hash) != 64 {
				t.Fatalf("HashForStorage length = %d, want 64", len(hash))
			}

			// Deterministic: same input → same output
			hash2 := HashForStorage(tt.token)
			if hash != hash2 {
				t.Fatalf("HashForStorage not deterministic: %s != %s", hash, hash2)
			}

			// Hash differs from input (unless input is already a SHA-256 hex)
			if tt.token != "" && hash == tt.token {
				t.Fatal("HashForStorage returned the input — hash should differ")
			}
		})
	}
}

func TestHashForStorageDiffersForDifferentInputs(t *testing.T) {
	t.Parallel()

	h1 := HashForStorage("token-a")
	h2 := HashForStorage("token-b")
	if h1 == h2 {
		t.Fatal("HashForStorage returned same hash for different inputs")
	}
}
