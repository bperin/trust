package aead

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestAES256GCM_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	a, err := NewAES256GCM(key)
	if err != nil {
		t.Fatalf("NewAES256GCM error: %v", err)
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
			ct, err := a.Encrypt(tt.plaintext, tt.versionType)
			if err != nil {
				t.Fatalf("Encrypt error: %v", err)
			}
			pt, err := a.Decrypt(ct, tt.versionType)
			if err != nil {
				t.Fatalf("Decrypt error: %v", err)
			}
			if subtle.ConstantTimeCompare(pt, tt.plaintext) != 1 {
				t.Errorf("round-trip mismatch: got %x, want %x", pt, tt.plaintext)
			}
		})
	}
}

func TestAES256GCM_DecryptFailures(t *testing.T) {
	a, err := NewAES256GCM(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewAES256GCM: %v", err)
	}
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	aWrong, err := NewAES256GCM(wrongKey)
	if err != nil {
		t.Fatalf("NewAES256GCM wrong key: %v", err)
	}

	ct, err := a.Encrypt([]byte("secret"), []byte("v1"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tests := []struct {
		name      string
		ct        []byte
		version   []byte
		decrypter *AES256GCM
		want      error
	}{
		{
			name:      "tampered ciphertext",
			ct:        tamperLastByte(ct),
			version:   []byte("v1"),
			decrypter: a,
			want:      ErrDecrypt,
		},
		{
			name:      "wrong versionType",
			ct:        ct,
			version:   []byte("v2"),
			decrypter: a,
			want:      ErrDecrypt,
		},
		{
			name:      "wrong key",
			ct:        ct,
			version:   []byte("v1"),
			decrypter: aWrong,
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

// tamperLastByte returns a copy of ct with the last byte flipped.
func tamperLastByte(ct []byte) []byte {
	out := make([]byte, len(ct))
	copy(out, ct)
	out[len(out)-1] ^= 0x01
	return out
}

func TestAES256GCM_ShortCiphertext(t *testing.T) {
	a, _ := NewAES256GCM(make([]byte, 32))

	tests := []struct {
		name string
		ct   []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte("short")},
		{"just nonce", make([]byte, 12)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := a.Decrypt(tt.ct, []byte("v1"))
			if err == nil {
				t.Fatal("short ciphertext decrypted — should fail")
			}
			if !errors.Is(err, ErrCiphertextTooShort) {
				t.Errorf("error = %v, want ErrCiphertextTooShort", err)
			}
		})
	}
}

func TestAES256GCM_InvalidKey(t *testing.T) {
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
			_, err := NewAES256GCM(tt.key)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("error = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestAES256GCM_NonceUniqueness(t *testing.T) {
	a, _ := NewAES256GCM(make([]byte, 32))

	seen := make(map[[12]byte]bool, 1000)
	for i := 0; i < 1000; i++ {
		ct, err := a.Encrypt([]byte("test"), []byte("v1"))
		if err != nil {
			t.Fatalf("Encrypt iteration %d error: %v", i, err)
		}
		var nonce [12]byte
		copy(nonce[:], ct[:12])
		if seen[nonce] {
			t.Fatalf("nonce collision at iteration %d", i)
		}
		seen[nonce] = true
	}
}

func TestAES256GCM_DifferentPlaintextsProduceDifferentCiphertexts(t *testing.T) {
	a, _ := NewAES256GCM(make([]byte, 32))

	ct1, _ := a.Encrypt([]byte("message1"), []byte("v1"))
	ct2, _ := a.Encrypt([]byte("message2"), []byte("v1"))

	if subtle.ConstantTimeCompare(ct1, ct2) == 1 {
		t.Fatal("different plaintexts produced identical ciphertext")
	}
}

// TestAES256GCM_NISTVectors exercises the raw GCM cipher (accessed via the
// unexported gcm field) against the known-answer vectors from [SP 800-38D]
// Appendix B, Test Cases 13–16 (AES-256-GCM). The wrapper generates random
// nonces, so the fixed-nonce path is tested directly here; the wrapper
// round-trip is covered by TestAES256GCM_RoundTrip.
//
// Vector source: "The Galois/Counter Mode of Operation (GCM)",
// McGrew & Viega, Appendix B — reproduced in NIST SP 800-38D Appendix B.
func TestAES256GCM_NISTVectors(t *testing.T) {
	tests := []struct {
		name      string
		key       string // hex
		nonce     string // hex (12 bytes)
		plaintext string // hex
		aad       string // hex
		wantCT    string // hex (ciphertext || tag)
	}{
		{
			// Vector: [SP 800-38D] Appendix B Test Case 13
			name:      "TC13: AES-256, empty plaintext, no AAD",
			key:       "0000000000000000000000000000000000000000000000000000000000000000",
			nonce:     "000000000000000000000000",
			plaintext: "",
			aad:       "",
			wantCT:    "530f8afbc74536b9a963b4f1c4cb738b",
		},
		{
			// Vector: [SP 800-38D] Appendix B Test Case 14
			name:      "TC14: AES-256, 16-byte plaintext, no AAD",
			key:       "0000000000000000000000000000000000000000000000000000000000000000",
			nonce:     "000000000000000000000000",
			plaintext: "00000000000000000000000000000000",
			aad:       "",
			wantCT:    "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
		},
		{
			// Vector: [SP 800-38D] Appendix B Test Case 15
			name:      "TC15: AES-256, 64-byte plaintext, no AAD",
			key:       "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			nonce:     "cafebabefacedbaddecaf888",
			plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
			aad:       "",
			wantCT:    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c",
		},
		{
			// Vector: [SP 800-38D] Appendix B Test Case 16
			name:      "TC16: AES-256, 60-byte plaintext, 20-byte AAD",
			key:       "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			nonce:     "cafebabefacedbaddecaf888",
			plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			aad:       "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			wantCT:    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := hex.DecodeString(tt.key)
			if err != nil {
				t.Fatalf("hex decode key: %v", err)
			}
			a, err := NewAES256GCM(key)
			if err != nil {
				t.Fatalf("NewAES256GCM: %v", err)
			}

			nonce, err := hex.DecodeString(tt.nonce)
			if err != nil {
				t.Fatalf("hex decode nonce: %v", err)
			}
			plaintext, err := hex.DecodeString(tt.plaintext)
			if err != nil {
				t.Fatalf("hex decode plaintext: %v", err)
			}
			aad, err := hex.DecodeString(tt.aad)
			if err != nil {
				t.Fatalf("hex decode aad: %v", err)
			}
			wantCT, err := hex.DecodeString(tt.wantCT)
			if err != nil {
				t.Fatalf("hex decode wantCT: %v", err)
			}

			// Test the raw GCM path with the fixed nonce from the vector.
			gotCT := a.gcm.Seal(nil, nonce, plaintext, aad)
			if subtle.ConstantTimeCompare(gotCT, wantCT) != 1 {
				t.Errorf("Seal mismatch:\n got %x\n want %x", gotCT, wantCT)
			}

			// Verify the reverse: Open must recover the original plaintext.
			gotPT, err := a.gcm.Open(nil, nonce, gotCT, aad)
			if err != nil {
				t.Fatalf("Open error: %v", err)
			}
			if subtle.ConstantTimeCompare(gotPT, plaintext) != 1 {
				t.Errorf("Open mismatch:\n got %x\n want %x", gotPT, plaintext)
			}
		})
	}
}
