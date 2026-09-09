package aead

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestXChaCha20_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	x, err := NewXChaCha20Poly1305(key)
	if err != nil {
		t.Fatalf("NewXChaCha20Poly1305 error: %v", err)
	}

	tests := []struct {
		name        string
		plaintext   []byte
		versionType []byte
	}{
		{"short message", []byte("hello world"), []byte("v1")},
		{"empty plaintext", []byte{}, []byte("v1")},
		{"nil plaintext", nil, []byte("v1")},
		{"large message", []byte(strings.Repeat("x", 100000)), []byte("v1")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := x.Encrypt(tt.plaintext, tt.versionType)
			if err != nil {
				t.Fatalf("Encrypt error: %v", err)
			}
			pt, err := x.Decrypt(ct, tt.versionType)
			if err != nil {
				t.Fatalf("Decrypt error: %v", err)
			}
			if subtle.ConstantTimeCompare(pt, tt.plaintext) != 1 {
				t.Errorf("round-trip mismatch: got %x, want %x", pt, tt.plaintext)
			}
		})
	}
}

// TestXChaCha20_KnownVector validates Decrypt against the published
// draft-irtf-cfrg-xchacha §A.3.3 test vector (Wycheproof tcId 1,
// "draft-arciszewski-xchacha-02"). The key, nonce, AAD, plaintext, and
// ciphertext||tag are all independently published constants — this is not
// a self-consistency check. Encrypt uses a random nonce, so the known
// vector exercises the Decrypt/framing path: nonce(24) || ct || tag(16).
func TestXChaCha20_KnownVector(t *testing.T) {
	key, err := hex.DecodeString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	nonce, err := hex.DecodeString("404142434445464748494a4b4c4d4e4f5051525354555657")
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	aad, err := hex.DecodeString("50515253c0c1c2c3c4c5c6c7")
	if err != nil {
		t.Fatalf("decode aad: %v", err)
	}
	wantPlaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	ct, err := hex.DecodeString("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e")
	if err != nil {
		t.Fatalf("decode ct: %v", err)
	}
	tag, err := hex.DecodeString("c0875924c1c7987947deafd8780acf49")
	if err != nil {
		t.Fatalf("decode tag: %v", err)
	}

	// Blob format: nonce || ciphertext || tag.
	blob := make([]byte, 0, len(nonce)+len(ct)+len(tag))
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	blob = append(blob, tag...)

	x, err := NewXChaCha20Poly1305(key)
	if err != nil {
		t.Fatalf("NewXChaCha20Poly1305 error: %v", err)
	}

	pt, err := x.Decrypt(blob, aad)
	if err != nil {
		t.Fatalf("Decrypt known vector error: %v", err)
	}
	if subtle.ConstantTimeCompare(pt, wantPlaintext) != 1 {
		t.Errorf("known vector mismatch: got %q, want %q", pt, wantPlaintext)
	}
}

func TestXChaCha20_DecryptFailures(t *testing.T) {
	x, err := NewXChaCha20Poly1305(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewXChaCha20Poly1305: %v", err)
	}
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	xWrong, err := NewXChaCha20Poly1305(wrongKey)
	if err != nil {
		t.Fatalf("NewXChaCha20Poly1305 wrong key: %v", err)
	}

	ct, err := x.Encrypt([]byte("secret"), []byte("v1"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tests := []struct {
		name      string
		ct        []byte
		version   []byte
		decrypter *XChaCha20Poly1305
		want      error
	}{
		{
			name:      "tampered ciphertext",
			ct:        tamperLastByte(ct),
			version:   []byte("v1"),
			decrypter: x,
			want:      ErrDecrypt,
		},
		{
			name:      "wrong versionType",
			ct:        ct,
			version:   []byte("v2"),
			decrypter: x,
			want:      ErrDecrypt,
		},
		{
			name:      "wrong key",
			ct:        ct,
			version:   []byte("v1"),
			decrypter: xWrong,
			want:      ErrDecrypt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.decrypter.Decrypt(tt.ct, tt.version)
			if err == nil {
				t.Fatal("decryption succeeded — should fail")
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestXChaCha20_ShortCiphertext(t *testing.T) {
	x, _ := NewXChaCha20Poly1305(make([]byte, 32))

	tests := []struct {
		name string
		ct   []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte("short")},
		{"just nonce", make([]byte, 24)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := x.Decrypt(tt.ct, []byte("v1"))
			if err == nil {
				t.Fatal("short ciphertext decrypted — should fail")
			}
			if !errors.Is(err, ErrCiphertextTooShort) {
				t.Errorf("error = %v, want ErrCiphertextTooShort", err)
			}
		})
	}
}

func TestXChaCha20_InvalidKey(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", make([]byte, 16)},
		{"too long", make([]byte, 33)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewXChaCha20Poly1305(tt.key)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("error = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestXChaCha20_NonceUniqueness(t *testing.T) {
	x, _ := NewXChaCha20Poly1305(make([]byte, 32))

	seen := make(map[[24]byte]bool, 1000)
	for i := 0; i < 1000; i++ {
		ct, err := x.Encrypt([]byte("test"), []byte("v1"))
		if err != nil {
			t.Fatalf("Encrypt iteration %d error: %v", i, err)
		}
		var nonce [24]byte
		copy(nonce[:], ct[:24])
		if seen[nonce] {
			t.Fatalf("nonce collision at iteration %d", i)
		}
		seen[nonce] = true
	}
}

func TestXChaCha20_DifferentPlaintextsProduceDifferentCiphertexts(t *testing.T) {
	x, _ := NewXChaCha20Poly1305(make([]byte, 32))

	ct1, _ := x.Encrypt([]byte("message1"), []byte("v1"))
	ct2, _ := x.Encrypt([]byte("message2"), []byte("v1"))

	if subtle.ConstantTimeCompare(ct1, ct2) == 1 {
		t.Fatal("different plaintexts produced identical ciphertext")
	}
}
