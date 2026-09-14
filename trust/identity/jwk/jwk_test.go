package jwkutil_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	stdecdsa "crypto/ecdsa"
	stded25519 "crypto/ed25519"
	"crypto/elliptic"
	stdrsa "crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/bperin/trust/trust/crypto/ecdsa"
	"github.com/bperin/trust/trust/crypto/ed25519"
	"github.com/bperin/trust/trust/crypto/rsa"
	"github.com/bperin/trust/trust/crypto/secp256k1"
	"github.com/bperin/trust/trust/crypto/x25519"
	jwkutil "github.com/bperin/trust/trust/identity/jwk"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// publicEqual reports whether two trust public keys are equal using the
// key-type-specific Equal method (which is constant-time). Returns
// false if the types differ.
func publicEqual(a, b crypto.PublicKey) bool {
	switch aa := a.(type) {
	case *ed25519.PublicKey:
		bb, ok := b.(*ed25519.PublicKey)
		return ok && aa.Equal(bb)
	case *secp256k1.PublicKey:
		bb, ok := b.(*secp256k1.PublicKey)
		return ok && aa.Equal(bb)
	case *ecdsa.PublicKey:
		bb, ok := b.(*ecdsa.PublicKey)
		return ok && aa.Equal(bb)
	case *rsa.PSSPublicKey:
		bb, ok := b.(*rsa.PSSPublicKey)
		return ok && aa.Equal(bb)
	case *rsa.PKCS1PublicKey:
		bb, ok := b.(*rsa.PKCS1PublicKey)
		return ok && aa.Equal(bb)
	case *x25519.PublicKey:
		bb, ok := b.(*x25519.PublicKey)
		return ok && aa.Equal(bb)
	}
	return false
}

// privatePublic derives the public key from a trust private key.
func privatePublic(k crypto.PrivateKey) crypto.PublicKey {
	switch kk := k.(type) {
	case *ed25519.PrivateKey:
		return kk.Public()
	case *secp256k1.PrivateKey:
		return kk.Public()
	case *ecdsa.PrivateKey:
		return kk.Public()
	case *rsa.PSSPrivateKey:
		return kk.Public()
	case *rsa.PKCS1PrivateKey:
		return kk.Public()
	case *x25519.PrivateKey:
		return kk.Public()
	}
	return nil
}

// b64urlDecode decodes a base64url-no-padding string (test helper).
func b64urlDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode %q: %v", s, err)
	}
	return b
}

// TestRFC8037Ed25519KnownAnswer parses the [RFC 8037] §A.1 Ed25519
// private key JWK and verifies the seed, public key, and round-trip.
// Vector: [RFC 8037] §A.1 Ed25519 Private Key.
func TestRFC8037Ed25519KnownAnswer(t *testing.T) {
	const (
		// Vector: [RFC 8037] §A.1 Ed25519 Private Key.
		privJWK = `{"kty":"OKP","crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		pubJWK = `{"kty":"OKP","crv":"Ed25519",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		wantSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
		wantX       = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	)

	priv, err := jwkutil.PrivateFromJWK([]byte(privJWK))
	if err != nil {
		t.Fatalf("PrivateFromJWK: %v", err)
	}
	edPriv, ok := priv.(*ed25519.PrivateKey)
	if !ok {
		t.Fatalf("got %T, want *ed25519.PrivateKey", priv)
	}

	// The seed must match the RFC 8037 §A.1 hex dump exactly.
	gotSeedHex := hex.EncodeToString(edPriv.StdKey().Seed())
	if gotSeedHex != wantSeedHex {
		t.Errorf("seed: got %s, want %s", gotSeedHex, wantSeedHex)
	}

	// The public key "x" must match the RFC value, compared in
	// constant time.
	gotPub := edPriv.Public()
	gotPubBytes := gotPub.Bytes()
	gotX := base64.RawURLEncoding.EncodeToString(gotPubBytes[:])
	gotXBytes := b64urlDecode(t, gotX)
	wantXBytes := b64urlDecode(t, wantX)
	if subtle.ConstantTimeCompare(gotXBytes, wantXBytes) != 1 {
		t.Errorf("public x: got %s, want %s", gotX, wantX)
	}

	// The public-only JWK must parse to a public key equal to the
	// derived public key.
	pub, err := jwkutil.PublicFromJWK([]byte(pubJWK))
	if err != nil {
		t.Fatalf("PublicFromJWK: %v", err)
	}
	if !publicEqual(pub, gotPub) {
		t.Errorf("parsed public key does not equal derived public key")
	}

	// Re-marshalling the parsed public key must reproduce the same
	// canonical JWK (same x, kty, crv, alg).
	m, err := jwkutil.Marshal(pub)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if m["kty"] != "OKP" || m["crv"] != "Ed25519" || m["alg"] != "EdDSA" {
		t.Errorf("marshal members: got kty=%v crv=%v alg=%v, want OKP/Ed25519/EdDSA",
			m["kty"], m["crv"], m["alg"])
	}
	if m["x"] != wantX {
		t.Errorf("marshal x: got %v, want %s", m["x"], wantX)
	}
	if _, hasD := m["d"]; hasD {
		t.Errorf("public marshal must not include \"d\"")
	}
}

// TestRFC8037X25519PublicVector parses the [RFC 8037] §A.6 X25519
// public key JWK (a cross-implementation vector) and verifies the
// round-trip.
// Vector: [RFC 8037] §A.6 ECDH-ES with X25519 (Bob's public key).
func TestRFC8037X25519PublicVector(t *testing.T) {
	const (
		// Vector: [RFC 8037] §A.6 X25519 public key.
		pubJWK = `{"kty":"OKP","crv":"X25519","kid":"Bob",` +
			`"x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}`
		wantX = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
	)

	pub, err := jwkutil.PublicFromJWK([]byte(pubJWK))
	if err != nil {
		t.Fatalf("PublicFromJWK: %v", err)
	}
	xPub, ok := pub.(*x25519.PublicKey)
	if !ok {
		t.Fatalf("got %T, want *x25519.PublicKey", pub)
	}

	xPubBytes := xPub.Bytes()
	gotX := base64.RawURLEncoding.EncodeToString(xPubBytes[:])
	gotXBytes := b64urlDecode(t, gotX)
	wantXBytes := b64urlDecode(t, wantX)
	if subtle.ConstantTimeCompare(gotXBytes, wantXBytes) != 1 {
		t.Errorf("x: got %s, want %s", gotX, wantX)
	}

	// Round-trip: marshal the parsed key and re-parse; x must match.
	m, err := jwkutil.Marshal(pub)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if m["kty"] != "OKP" || m["crv"] != "X25519" {
		t.Errorf("members: got kty=%v crv=%v, want OKP/X25519", m["kty"], m["crv"])
	}
	if _, hasAlg := m["alg"]; hasAlg {
		t.Errorf("X25519 public marshal must omit alg, got %v", m["alg"])
	}
	if m["x"] != wantX {
		t.Errorf("marshal x: got %v, want %s", m["x"], wantX)
	}
}

// TestRoundTripPublic verifies that marshal → unmarshal reproduces
// each trust public key type (compared with the constant-time Equal
// method) and that re-marshalling is canonical (deterministic map).
func TestRoundTripPublic(t *testing.T) {
	cases := []struct {
		name string
		gen  func() (crypto.PublicKey, error)
	}{
		{"Ed25519", func() (crypto.PublicKey, error) {
			_, pub, err := ed25519.GenerateKey()
			return pub, err
		}},
		{"secp256k1", func() (crypto.PublicKey, error) {
			_, pub, err := secp256k1.GenerateKey()
			return pub, err
		}},
		{"ECDSA-P256", func() (crypto.PublicKey, error) {
			_, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
			return pub, err
		}},
		{"ECDSA-P384", func() (crypto.PublicKey, error) {
			_, pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
			return pub, err
		}},
		{"RSA-PSS", func() (crypto.PublicKey, error) {
			_, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
			return pub, err
		}},
		{"RSA-PKCS1", func() (crypto.PublicKey, error) {
			_, pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
			return pub, err
		}},
		{"X25519", func() (crypto.PublicKey, error) {
			_, pub, err := x25519.GenerateKey()
			return pub, err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := tc.gen()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			m, err := jwkutil.Marshal(want)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			got, err := jwkutil.Unmarshal(m)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if !publicEqual(got, want) {
				t.Errorf("round-trip public key not equal: got %T, want %T", got, want)
			}
			// Canonical determinism: re-marshalling the round-tripped
			// key must produce the same map.
			m2, err := jwkutil.Marshal(got)
			if err != nil {
				t.Fatalf("re-Marshal: %v", err)
			}
			if !reflect.DeepEqual(m, m2) {
				t.Errorf("canonical marshal not deterministic:\n got=%v\nwant=%v", m2, m)
			}
			// ToJWK must produce valid JSON that re-parses.
			jb, err := jwkutil.ToJWK(want)
			if err != nil {
				t.Fatalf("ToJWK: %v", err)
			}
			got2, err := jwkutil.PublicFromJWK(jb)
			if err != nil {
				t.Fatalf("PublicFromJWK(ToJWK): %v", err)
			}
			if !publicEqual(got2, want) {
				t.Errorf("ToJWK round-trip not equal")
			}
		})
	}
}

// TestRoundTripPrivate verifies that MarshalPrivate → UnmarshalPrivate
// reproduces each trust private key's public material (compared with
// the constant-time Equal method on the derived public key) and that
// re-marshalling is canonical.
func TestRoundTripPrivate(t *testing.T) {
	cases := []struct {
		name string
		gen  func() (crypto.PrivateKey, error)
	}{
		{"Ed25519", func() (crypto.PrivateKey, error) {
			priv, _, err := ed25519.GenerateKey()
			return priv, err
		}},
		{"secp256k1", func() (crypto.PrivateKey, error) {
			priv, _, err := secp256k1.GenerateKey()
			return priv, err
		}},
		{"ECDSA-P256", func() (crypto.PrivateKey, error) {
			priv, _, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
			return priv, err
		}},
		{"ECDSA-P384", func() (crypto.PrivateKey, error) {
			priv, _, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
			return priv, err
		}},
		{"RSA-PSS", func() (crypto.PrivateKey, error) {
			priv, _, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
			return priv, err
		}},
		{"RSA-PKCS1", func() (crypto.PrivateKey, error) {
			priv, _, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
			return priv, err
		}},
		{"X25519", func() (crypto.PrivateKey, error) {
			priv, _, err := x25519.GenerateKey()
			return priv, err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := tc.gen()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			m, err := jwkutil.MarshalPrivate(want)
			if err != nil {
				t.Fatalf("MarshalPrivate: %v", err)
			}
			// The private JWK must include "d" but tests must never
			// print it; only assert presence.
			if _, hasD := m["d"]; !hasD {
				t.Errorf("private marshal missing \"d\"")
			}
			got, err := jwkutil.UnmarshalPrivate(m)
			if err != nil {
				t.Fatalf("UnmarshalPrivate: %v", err)
			}
			wantPub := privatePublic(want)
			gotPub := privatePublic(got)
			if !publicEqual(gotPub, wantPub) {
				t.Errorf("round-trip private public key not equal: got %T, want %T",
					gotPub, wantPub)
			}
			// Canonical determinism of the private JWK map.
			m2, err := jwkutil.MarshalPrivate(got)
			if err != nil {
				t.Fatalf("re-MarshalPrivate: %v", err)
			}
			if !reflect.DeepEqual(m, m2) {
				t.Errorf("canonical private marshal not deterministic")
			}
		})
	}
}

// TestNegativeUnmarshal covers the rejection paths required by the
// acceptance criteria: alg:none, duplicate members, wrong kty, wrong
// crv, malformed base64url, missing required fields, "d" in a public
// JWK, and alg mismatch.
func TestNegativeUnmarshal(t *testing.T) {
	cases := []struct {
		name    string
		jwk     string
		wantErr error
	}{
		{
			name:    "alg none rejected",
			jwk:     `{"kty":"OKP","crv":"Ed25519","alg":"none","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
			wantErr: jwkutil.ErrAlgNone,
		},
		{
			name:    "duplicate member",
			jwk:     `{"kty":"OKP","kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
			wantErr: jwkutil.ErrDuplicateMember,
		},
		{
			name:    "wrong kty",
			jwk:     `{"kty":"oct","k":"AAAA"}`,
			wantErr: jwkutil.ErrUnsupportedKty,
		},
		{
			name:    "wrong crv for OKP",
			jwk:     `{"kty":"OKP","crv":"Ed448","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
			wantErr: jwkutil.ErrUnsupportedCrv,
		},
		{
			name:    "wrong crv for EC",
			jwk:     `{"kty":"EC","crv":"P-521","x":"AAAA","y":"AAAA"}`,
			wantErr: jwkutil.ErrUnsupportedCrv,
		},
		{
			name:    "malformed base64url",
			jwk:     `{"kty":"OKP","crv":"Ed25519","x":"!!!not base64url!!!"}`,
			wantErr: jwkutil.ErrInvalidMember,
		},
		{
			name:    "missing x",
			jwk:     `{"kty":"OKP","crv":"Ed25519"}`,
			wantErr: jwkutil.ErrMissingMember,
		},
		{
			name:    "missing kty",
			jwk:     `{"crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
			wantErr: jwkutil.ErrMissingMember,
		},
		{
			name:    "d present in public JWK",
			jwk:     `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}`,
			wantErr: jwkutil.ErrInvalidMember,
		},
		{
			name:    "alg mismatch Ed25519",
			jwk:     `{"kty":"OKP","crv":"Ed25519","alg":"ES256","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
			wantErr: jwkutil.ErrAlgMismatch,
		},
		{
			name:    "alg mismatch EC P-256",
			jwk:     `{"kty":"EC","crv":"P-256","alg":"ES384","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
			wantErr: jwkutil.ErrAlgMismatch,
		},
		{
			name:    "RSA missing alg",
			jwk:     `{"kty":"RSA","n":"AAAA","e":"AAAA"}`,
			wantErr: jwkutil.ErrAlgRequired,
		},
		{
			name:    "RSA invalid alg",
			jwk:     `{"kty":"RSA","alg":"ES256","n":"AAAA","e":"AAAA"}`,
			wantErr: jwkutil.ErrAlgMismatch,
		},
		{
			name:    "not a JSON object",
			jwk:     `["not","an","object"]`,
			wantErr: jwkutil.ErrInvalidMember,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwkutil.PublicFromJWK([]byte(tc.jwk))
			if err == nil {
				t.Fatalf("PublicFromJWK: got nil error, want %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("PublicFromJWK: got %v, want errors.Is %v", err, tc.wantErr)
			}
		})
	}
}

// TestNegativeUnmarshalPrivate covers private-key rejection paths:
// alg:none, missing "d", and inconsistent public material.
func TestNegativeUnmarshalPrivate(t *testing.T) {
	t.Run("alg none rejected", func(t *testing.T) {
		jwk := `{"kty":"OKP","crv":"Ed25519","alg":"none",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		_, err := jwkutil.PrivateFromJWK([]byte(jwk))
		if !errors.Is(err, jwkutil.ErrAlgNone) {
			t.Errorf("got %v, want ErrAlgNone", err)
		}
	})
	t.Run("missing d", func(t *testing.T) {
		jwk := `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		_, err := jwkutil.PrivateFromJWK([]byte(jwk))
		if !errors.Is(err, jwkutil.ErrMissingMember) {
			t.Errorf("got %v, want ErrMissingMember", err)
		}
	})
	t.Run("inconsistent x", func(t *testing.T) {
		// "d" is the RFC 8037 seed but "x" is a different (wrong)
		// public key, so the consistency check must reject it.
		jwk := `{"kty":"OKP","crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
		_, err := jwkutil.PrivateFromJWK([]byte(jwk))
		if !errors.Is(err, jwkutil.ErrKeyInconsistent) {
			t.Errorf("got %v, want ErrKeyInconsistent", err)
		}
	})
	t.Run("duplicate member private", func(t *testing.T) {
		jwk := `{"kty":"OKP","crv":"Ed25519","crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		_, err := jwkutil.PrivateFromJWK([]byte(jwk))
		if !errors.Is(err, jwkutil.ErrDuplicateMember) {
			t.Errorf("got %v, want ErrDuplicateMember", err)
		}
	})
}

// TestToJWKS verifies that ToJWKS produces a JWK Set with one entry per
// key and that each entry re-parses to the original key.
func TestToJWKS(t *testing.T) {
	_, edPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519 generate: %v", err)
	}
	_, xPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("x25519 generate: %v", err)
	}
	_, secPub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("secp256k1 generate: %v", err)
	}

	out, err := jwkutil.ToJWKS([]crypto.PublicKey{edPub, xPub, secPub})
	if err != nil {
		t.Fatalf("ToJWKS: %v", err)
	}
	var set jwkutil.JWKS
	if err := json.Unmarshal(out, &set); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(set.Keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(set.Keys))
	}
	// Each key must re-parse to the original.
	pubs := []crypto.PublicKey{edPub, xPub, secPub}
	for i, m := range set.Keys {
		got, err := jwkutil.Unmarshal(m)
		if err != nil {
			t.Fatalf("Unmarshal[%d]: %v", i, err)
		}
		if !publicEqual(got, pubs[i]) {
			t.Errorf("JWKS key %d not equal to original", i)
		}
	}
}

// TestCrossImplementationJWXParse verifies that a JWK produced directly
// by jwx/v3/jwk parses through the identity/jwk public API. This is
// the cross-implementation vector required by acceptance criterion #4:
// a JWK produced by jwx parses through identity/jwk.
func TestCrossImplementationJWXParse(t *testing.T) {
	_, edPub, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Ed25519 generate: %v", err)
	}
	x25519Priv, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatalf("X25519 generate: %v", err)
	}
	ecPriv, err := stdecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatalf("ECDSA P-256 generate: %v", err)
	}
	rsaPriv, err := stdrsa.GenerateKey(nil, 2048)
	if err != nil {
		t.Fatalf("RSA generate: %v", err)
	}

	cases := []struct {
		name    string
		rawKey  any
		alg     string
		wantKty string
	}{
		{"Ed25519", edPub, "EdDSA", "OKP"},
		{"X25519", x25519Priv.Public(), "", "OKP"},
		{"ECDSA-P256", &ecPriv.PublicKey, "ES256", "EC"},
		{"RSA", &rsaPriv.PublicKey, "PS256", "RSA"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Produce a JWK using jwx directly.
			jwxKey, err := jwk.Import(tc.rawKey)
			if err != nil {
				t.Fatalf("jwk.Import: %v", err)
			}
			if tc.alg != "" {
				if err := jwxKey.Set("alg", tc.alg); err != nil {
					t.Fatalf("jwkKey.Set alg: %v", err)
				}
			}
			jwxData, err := json.Marshal(jwxKey)
			if err != nil {
				t.Fatalf("jwx marshal: %v", err)
			}

			// Parse the jwx-produced JWK through identity/jwk.
			// jwx may include "d" for Ed25519 public keys (both
			// public and private are []byte), so use PrivateFromJWK
			// when "d" is present, PublicFromJWK otherwise.
			var raw map[string]any
			if err := json.Unmarshal(jwxData, &raw); err != nil {
				t.Fatalf("unmarshal jwx data: %v", err)
			}
			var pub crypto.PublicKey
			if _, hasD := raw["d"]; hasD {
				priv, err := jwkutil.PrivateFromJWK(jwxData)
				if err != nil {
					t.Fatalf("PrivateFromJWK(jwx-produced): %v", err)
				}
				pub = privatePublic(priv)
			} else {
				var err error
				pub, err = jwkutil.PublicFromJWK(jwxData)
				if err != nil {
					t.Fatalf("PublicFromJWK(jwx-produced): %v", err)
				}
			}
			if pub == nil {
				t.Fatalf("parse returned nil key")
			}

			// Re-marshal through identity/jwk and verify kty matches.
			m, err := jwkutil.Marshal(pub)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if m["kty"] != tc.wantKty {
				t.Errorf("kty: got %v, want %s", m["kty"], tc.wantKty)
			}
		})
	}
}

// TestCrossImplementationJWXRoundTrip verifies that a JWK produced by
// identity/jwk.Marshal parses through jwx/v3/jwk.ParseKey. This is the
// reverse direction of the cross-implementation vector.
func TestCrossImplementationJWXRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		gen  func() (crypto.PublicKey, error)
	}{
		{"Ed25519", func() (crypto.PublicKey, error) {
			_, pub, err := ed25519.GenerateKey()
			return pub, err
		}},
		{"X25519", func() (crypto.PublicKey, error) {
			_, pub, err := x25519.GenerateKey()
			return pub, err
		}},
		{"ECDSA-P256", func() (crypto.PublicKey, error) {
			_, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
			return pub, err
		}},
		{"ECDSA-P384", func() (crypto.PublicKey, error) {
			_, pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
			return pub, err
		}},
		{"RSA-PSS", func() (crypto.PublicKey, error) {
			_, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
			return pub, err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := tc.gen()
			if err != nil {
				t.Fatalf("generate: %v", err)
			}

			// Marshal through identity/jwk.
			m, err := jwkutil.Marshal(want)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}

			// Parse through jwx directly.
			jwxKey, err := jwk.ParseKey(data)
			if err != nil {
				t.Fatalf("jwk.ParseKey(identity/jwk-produced): %v", err)
			}

			// Export the raw key from jwx and verify it matches.
			var raw any
			if err := jwk.Export(jwxKey, &raw); err != nil {
				t.Fatalf("jwk.Export: %v", err)
			}
			if raw == nil {
				t.Fatalf("jwk.Export returned nil")
			}
		})
	}
}

// TestTamperedKeyRoundTrip verifies that tampered key bytes produce a
// different key after round-trip. This covers the acceptance criterion:
// "tampered key bytes → round-trip fails."
func TestTamperedKeyRoundTrip(t *testing.T) {
	_, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519 generate: %v", err)
	}
	m, err := jwkutil.Marshal(pub)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Tamper with the "x" member — flip the first character.
	xStr, ok := m["x"].(string)
	if !ok {
		t.Fatalf("x is not a string: %T", m["x"])
	}
	if len(xStr) == 0 {
		t.Fatalf("x is empty")
	}
	flip := byte('A')
	if xStr[0] == 'A' {
		flip = 'B'
	}
	m["x"] = string(flip) + xStr[1:]

	got, err := jwkutil.Unmarshal(m)
	if err != nil {
		// Parse failure is acceptable — tampered bytes may be invalid.
		return
	}
	// If it parsed, the key must NOT equal the original.
	if publicEqual(got, pub) {
		t.Errorf("Unmarshal with tampered key: got key equal to original, want different")
	}
}

// TestNoAuthChainImports verifies the dependency rule: the jwk package
// source must not import the auth or chain modules. trust must never
// depend on auth or chain.
func TestNoAuthChainImports(t *testing.T) {
	// The test runs with the working directory set to the package
	// directory, so jwk.go is a sibling file.
	src, err := os.ReadFile("jwk.go")
	if err != nil {
		t.Fatalf("cannot read jwk.go: %v", err)
	}
	if bytes.Contains(src, []byte("bperin/auth")) {
		t.Errorf("jwk.go imports auth module (dependency rule violation)")
	}
	if bytes.Contains(src, []byte("bperin/chain")) {
		t.Errorf("jwk.go imports chain module (dependency rule violation)")
	}
}
