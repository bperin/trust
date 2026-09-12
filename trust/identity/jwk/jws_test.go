package jwkutil

import (
	"crypto"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/signature"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// validClaims builds a payload with claims that pass the default checks.
func validClaims(t *testing.T) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"iss": "example-issuer",
		"aud": []string{"reader"},
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "user-1",
	})
	if err != nil {
		t.Fatalf("marshal claims: got error %v, want nil", err)
	}
	return payload
}

type roundTripKey struct {
	name    string
	alg     string
	priv    crypto.PrivateKey
	pub     crypto.PublicKey
	skipRSA bool
}

func roundTripKeys(t *testing.T) []roundTripKey {
	t.Helper()
	edPriv, edPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate Ed25519 key: got error %v, want nil", err)
	}
	k1Priv, k1Pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: got error %v, want nil", err)
	}
	p256Priv, p256Pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
	if err != nil {
		t.Fatalf("generate P-256 key: got error %v, want nil", err)
	}
	p384Priv, p384Pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
	if err != nil {
		t.Fatalf("generate P-384 key: got error %v, want nil", err)
	}
	ps256Priv, ps256Pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
	if err != nil {
		t.Fatalf("generate PSS-256 key: got error %v, want nil", err)
	}
	ps384Priv, ps384Pub, err := rsa.GeneratePSSKey(2048, crypto.SHA384)
	if err != nil {
		t.Fatalf("generate PSS-384 key: got error %v, want nil", err)
	}
	ps512Priv, ps512Pub, err := rsa.GeneratePSSKey(2048, crypto.SHA512)
	if err != nil {
		t.Fatalf("generate PSS-512 key: got error %v, want nil", err)
	}
	rs256Priv, rs256Pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
	if err != nil {
		t.Fatalf("generate PKCS1-256 key: got error %v, want nil", err)
	}
	rs384Priv, rs384Pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA384)
	if err != nil {
		t.Fatalf("generate PKCS1-384 key: got error %v, want nil", err)
	}
	rs512Priv, rs512Pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA512)
	if err != nil {
		t.Fatalf("generate PKCS1-512 key: got error %v, want nil", err)
	}
	return []roundTripKey{
		{name: "EdDSA", alg: "EdDSA", priv: edPriv, pub: edPub},
		{name: "ES256K", alg: "ES256K", priv: k1Priv, pub: k1Pub},
		{name: "ES256", alg: "ES256", priv: p256Priv, pub: p256Pub},
		{name: "ES384", alg: "ES384", priv: p384Priv, pub: p384Pub},
		{name: "PS256", alg: "PS256", priv: ps256Priv, pub: ps256Pub},
		{name: "PS384", alg: "PS384", priv: ps384Priv, pub: ps384Pub},
		{name: "PS512", alg: "PS512", priv: ps512Priv, pub: ps512Pub},
		{name: "RS256", alg: "RS256", priv: rs256Priv, pub: rs256Pub},
		{name: "RS384", alg: "RS384", priv: rs384Priv, pub: rs384Pub},
		{name: "RS512", alg: "RS512", priv: rs512Priv, pub: rs512Pub},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	payload := validClaims(t)
	for _, key := range roundTripKeys(t) {
		t.Run(key.name, func(t *testing.T) {
			t.Parallel()
			token, err := Sign(payload, key.priv, SignOptions{Algorithm: key.alg})
			if err != nil {
				t.Fatalf("Sign with %s: got error %v, want nil", key.alg, err)
			}
			if strings.Count(token, ".") != 2 {
				t.Errorf("compact serialization for %s: got %d dots, want 2", key.alg, strings.Count(token, "."))
			}
			got, err := Verify(token, key.pub, VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify with %s: got error %v, want nil", key.alg, err)
			}
			if string(got) != string(payload) {
				t.Errorf("payload for %s: got %q, want %q", key.alg, got, payload)
			}
			// Verifying with a pinned algorithm and claims must also pass.
			got, err = Verify(token, key.pub, VerifyOptions{
				Algorithm:        key.alg,
				ExpectedIssuer:   "example-issuer",
				ExpectedAudience: []string{"reader"},
			})
			if err != nil {
				t.Fatalf("Verify with %s and pinned options: got error %v, want nil", key.alg, err)
			}
			if string(got) != string(payload) {
				t.Errorf("pinned payload for %s: got %q, want %q", key.alg, got, payload)
			}
		})
	}
}

func TestSignNegative(t *testing.T) {
	t.Parallel()

	edPriv, edPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate Ed25519 key: got error %v, want nil", err)
	}
	p384Priv, _, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
	if err != nil {
		t.Fatalf("generate P-384 key: got error %v, want nil", err)
	}
	psPriv, _, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
	if err != nil {
		t.Fatalf("generate PSS key: got error %v, want nil", err)
	}

	tests := []struct {
		name     string
		key      crypto.PrivateKey
		opts     SignOptions
		wantErr  error
		wantAs   *signature.ErrAlgMismatch
	}{
		{name: "missing algorithm", key: edPriv, opts: SignOptions{}, wantErr: ErrAlgRequired},
		{name: "alg none", key: edPriv, opts: SignOptions{Algorithm: "none"}, wantErr: ErrAlgNone},
		{name: "alg in headers", key: edPriv, opts: SignOptions{Algorithm: "EdDSA", Headers: map[string]any{"alg": "EdDSA"}}, wantErr: ErrInvalidMember},
		{name: "crit in headers", key: edPriv, opts: SignOptions{Algorithm: "EdDSA", Headers: map[string]any{"crit": []string{"b64"}}}, wantErr: ErrInvalidMember},
		{name: "Ed25519 key with wrong alg", key: edPriv, opts: SignOptions{Algorithm: "ES256"}, wantAs: &signature.ErrAlgMismatch{}},
		{name: "P-384 key with ES256", key: p384Priv, opts: SignOptions{Algorithm: "ES256"}, wantAs: &signature.ErrAlgMismatch{}},
		{name: "PSS key with RS alg", key: psPriv, opts: SignOptions{Algorithm: "RS256"}, wantAs: &signature.ErrAlgMismatch{}},
		{name: "public key cannot sign", key: edPub, opts: SignOptions{Algorithm: "EdDSA"}, wantAs: &signature.ErrAlgMismatch{}},
		{name: "unknown algorithm", key: edPriv, opts: SignOptions{Algorithm: "HS256"}, wantErr: ErrUnsupportedAlg},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Sign([]byte("payload"), tt.key, tt.opts)
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Sign %s: got error %v, want errors.Is(_, %v)", tt.name, err, tt.wantErr)
			}
			if tt.wantAs != nil && !errors.As(err, &tt.wantAs) {
				t.Errorf("Sign %s: got error %v, want errors.As(_, %T)", tt.name, err, tt.wantAs)
			}
		})
	}
}

func TestVerifyNegative(t *testing.T) {
	t.Parallel()

	edPriv, edPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate Ed25519 key: got error %v, want nil", err)
	}
	_, k1Pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: got error %v, want nil", err)
	}
	_, rsPub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
	if err != nil {
		t.Fatalf("generate RSA key: got error %v, want nil", err)
	}

	goodPayload := validClaims(t)
	edToken, err := Sign(goodPayload, edPriv, SignOptions{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("sign EdDSA token: got error %v, want nil", err)
	}

	// Algorithm confusion: an HS256 token HMACed with the RSA public key
	// bytes as the secret must be refused by the alg pin before any
	// signature work. Vector: classic JWS alg-confusion attack.
	hsHeader := b64u([]byte(`{"alg":"HS256"}`))
	hsPayload := b64u(goodPayload)
	mac := hmac.New(sha256.New, []byte(fmt.Sprintf("%v", rsPub.N())))
	mac.Write([]byte(hsHeader + "." + hsPayload))
	hsToken := hsHeader + "." + hsPayload + "." + b64u(mac.Sum(nil))

	noneHeader := b64u([]byte(`{"alg":"none"}`))
	noneToken := noneHeader + "." + hsPayload + "."

	expiredPayload, _ := json.Marshal(map[string]any{"iss": "example-issuer", "exp": time.Now().Add(-time.Minute).Unix()})
	futurePayload, _ := json.Marshal(map[string]any{"iss": "example-issuer", "nbf": time.Now().Add(time.Hour).Unix()})
	futureIatPayload, _ := json.Marshal(map[string]any{"iss": "example-issuer", "iat": time.Now().Add(time.Hour).Unix()})
	wrongIssPayload, _ := json.Marshal(map[string]any{"iss": "evil-issuer", "exp": time.Now().Add(time.Hour).Unix()})
	wrongAudPayload, _ := json.Marshal(map[string]any{"iss": "example-issuer", "aud": "someone-else", "exp": time.Now().Add(time.Hour).Unix()})
	badExpTypePayload, _ := json.Marshal(map[string]any{"iss": "example-issuer", "exp": "tomorrow"})
	segments := strings.Split(edToken, ".")
	tamperedPayload := segments[0] + "." + b64u([]byte("{\"iss\":\"example-issuer\",\"exp\":9999999999}")) + "." + segments[2]
	sigBytes, _ := base64.RawURLEncoding.DecodeString(segments[2])
	if len(sigBytes) > 0 {
		sigBytes[0] ^= 0xff
	}
	tamperedSignature := segments[0] + "." + segments[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)
	paddedSegment := segments[0] + "=" + "." + segments[1] + "." + segments[2]
	nonCanonical := segments[0] + ".QR." + segments[2]

	expiredToken, err := Sign(expiredPayload, edPriv, SignOptions{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("sign expired token: got error %v, want nil", err)
	}
	futureToken, _ := Sign(futurePayload, edPriv, SignOptions{Algorithm: "EdDSA"})
	futureIatToken, _ := Sign(futureIatPayload, edPriv, SignOptions{Algorithm: "EdDSA"})
	wrongIssToken, _ := Sign(wrongIssPayload, edPriv, SignOptions{Algorithm: "EdDSA"})
	wrongAudToken, _ := Sign(wrongAudPayload, edPriv, SignOptions{Algorithm: "EdDSA"})
	badExpTypeToken, _ := Sign(badExpTypePayload, edPriv, SignOptions{Algorithm: "EdDSA"})

	tests := []struct {
		name    string
		token   string
		key     crypto.PublicKey
		opts    VerifyOptions
		wantErr error
	}{
		{name: "alg none", token: noneToken, key: edPub, wantErr: ErrAlgNone},
		{name: "HS256 confusion with RSA public key", token: hsToken, key: rsPub, wantErr: ErrAlgMismatch},
		{name: "wrong key type for token", token: edToken, key: k1Pub, wantErr: ErrAlgMismatch},
		{name: "caller pinned different algorithm", token: edToken, key: edPub, opts: VerifyOptions{Algorithm: "ES256K"}, wantErr: ErrAlgMismatch},
		{name: "tampered payload", token: tamperedPayload, key: edPub, wantErr: ErrInvalidSignature},
		{name: "tampered signature", token: tamperedSignature, key: edPub, wantErr: ErrInvalidSignature},
		{name: "padded segment", token: paddedSegment, key: edPub, wantErr: ErrInvalidSegment},
		{name: "non-canonical segment", token: nonCanonical, key: edPub, wantErr: ErrInvalidSegment},
		{name: "four segments", token: edToken + ".x", key: edPub, wantErr: ErrMalformedJWS},
		{name: "one segment", token: "abc", key: edPub, wantErr: ErrMalformedJWS},
		{name: "empty token", token: "", key: edPub, wantErr: ErrMalformedJWS},
		{name: "expired exp", token: expiredToken, key: edPub, wantErr: ErrExpired},
		{name: "future nbf", token: futureToken, key: edPub, wantErr: ErrNotYetValid},
		{name: "future iat", token: futureIatToken, key: edPub, wantErr: ErrNotYetValid},
		{name: "wrong issuer", token: wrongIssToken, key: edPub, opts: VerifyOptions{ExpectedIssuer: "example-issuer"}, wantErr: ErrIssuerMismatch},
		{name: "wrong audience", token: wrongAudToken, key: edPub, opts: VerifyOptions{ExpectedAudience: []string{"reader"}}, wantErr: ErrAudienceMismatch},
		{name: "non-numeric exp", token: badExpTypeToken, key: edPub, wantErr: ErrInvalidClaims},
		{name: "claims pin on opaque payload", token: mustSignOpaque(t, edPriv), key: edPub, opts: VerifyOptions{ExpectedIssuer: "example-issuer"}, wantErr: ErrInvalidClaims},
		{name: "nil key", token: edToken, key: nil, wantErr: ErrUnsupportedAlg},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Verify(tt.token, tt.key, tt.opts)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Verify %s: got error %v, want errors.Is(_, %v)", tt.name, err, tt.wantErr)
			}
		})
	}
}

func mustSignOpaque(t *testing.T, priv crypto.PrivateKey) string {
	t.Helper()
	token, err := Sign([]byte("not json"), priv, SignOptions{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("sign opaque payload: got error %v, want nil", err)
	}
	return token
}

func TestVerifyHeaderMemberNegative(t *testing.T) {
	t.Parallel()

	_, edPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate Ed25519 key: got error %v, want nil", err)
	}
	payload := b64u([]byte("x"))

	tests := []struct {
		name    string
		header  string
		wantErr error
	}{
		{name: "crit header", header: `{"alg":"EdDSA","crit":["b64"]}`, wantErr: ErrCritUnsupported},
		{name: "missing alg", header: `{"typ":"JWT"}`, wantErr: ErrMissingMember},
		{name: "alg not a string", header: `{"alg":123}`, wantErr: ErrInvalidMember},
		{name: "duplicate alg member", header: `{"alg":"EdDSA","alg":"EdDSA"}`, wantErr: ErrDuplicateMember},
		{name: "header not an object", header: `[1,2,3]`, wantErr: ErrInvalidMember},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			token := b64u([]byte(tt.header)) + "." + payload + ".AA"
			_, err := Verify(token, edPub, VerifyOptions{})
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Verify %s: got error %v, want errors.Is(_, %v)", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestSignDeterminism(t *testing.T) {
	t.Parallel()

	edPriv, _, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate Ed25519 key: got error %v, want nil", err)
	}
	k1Priv, k1Pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: got error %v, want nil", err)
	}
	payload := validClaims(t)

	first, err := Sign(payload, edPriv, SignOptions{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("first EdDSA sign: got error %v, want nil", err)
	}
	second, err := Sign(payload, edPriv, SignOptions{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("second EdDSA sign: got error %v, want nil", err)
	}
	if first != second {
		t.Errorf("EdDSA determinism: got %q and %q, want identical tokens", first, second)
	}

	esFirst, err := Sign(payload, k1Priv, SignOptions{Algorithm: "ES256K"})
	if err != nil {
		t.Fatalf("first ES256K sign: got error %v, want nil", err)
	}
	esSecond, err := Sign(payload, k1Priv, SignOptions{Algorithm: "ES256K"})
	if err != nil {
		t.Fatalf("second ES256K sign: got error %v, want nil", err)
	}
	// secp256k1 uses [RFC 6979] deterministic nonces, so ES256K is
	// reproducible like EdDSA.
	if esFirst != esSecond {
		t.Errorf("ES256K determinism: got %q and %q, want identical tokens", esFirst, esSecond)
	}
	if _, err := Verify(esFirst, k1Pub, VerifyOptions{}); err != nil {
		t.Errorf("Verify ES256K token %q: got error %v, want nil", esFirst, err)
	}

	// P-256 ECDSA is randomized: signatures differ but both verify.
	p256Priv, p256Pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
	if err != nil {
		t.Fatalf("generate P-256 key: got error %v, want nil", err)
	}
	ecFirst, err := Sign(payload, p256Priv, SignOptions{Algorithm: "ES256"})
	if err != nil {
		t.Fatalf("first ES256 sign: got error %v, want nil", err)
	}
	ecSecond, err := Sign(payload, p256Priv, SignOptions{Algorithm: "ES256"})
	if err != nil {
		t.Fatalf("second ES256 sign: got error %v, want nil", err)
	}
	if ecFirst == ecSecond {
		t.Errorf("ES256 randomization: got identical tokens %q, want different signatures", ecFirst)
	}
	for _, token := range []string{ecFirst, ecSecond} {
		if _, err := Verify(token, p256Pub, VerifyOptions{}); err != nil {
			t.Errorf("Verify randomized ES256 token %q: got error %v, want nil", token, err)
		}
	}
}

// TestRFC8037Ed25519Vector checks the [RFC 8037] Appendix A.4/A.5 JWS. The
// signing key is the [RFC 8032] Test Vector 1 key, so EdDSA is deterministic
// and our Sign must reproduce the exact compact serialization.
func TestRFC8037Ed25519Vector(t *testing.T) {
	t.Parallel()

	const token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
	publicJWK := []byte(`{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)
	privateJWK := []byte(`{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)

	got, err := VerifyWithJWK(token, publicJWK, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyWithJWK with RFC 8037 vector: got error %v, want nil", err)
	}
	if want := "Example of Ed25519 signing"; string(got) != want {
		t.Errorf("payload for RFC 8037 vector: got %q, want %q", got, want)
	}

	priv, err := PrivateFromJWK(privateJWK)
	if err != nil {
		t.Fatalf("PrivateFromJWK with RFC 8037 key: got error %v, want nil", err)
	}
	signed, err := Sign([]byte("Example of Ed25519 signing"), priv, SignOptions{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("Sign with RFC 8037 key: got error %v, want nil", err)
	}
	if signed != token {
		t.Errorf("deterministic EdDSA token: got %q, want %q", signed, token)
	}
}

// TestRFC7515RS256Vector checks the [RFC 7515] Appendix A.2 JWS. The vector
// payload expired in 2011, so it is checked through the signature path the
// full Verify uses; claim policy is application-level and covered separately.
func TestRFC7515RS256Vector(t *testing.T) {
	t.Parallel()

	const token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
	publicJWK := []byte(`{"kty":"RSA","alg":"RS256","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ","e":"AQAB"}`)

	key, err := PublicFromJWK(publicJWK)
	if err != nil {
		t.Fatalf("PublicFromJWK with RFC 7515 A.2 key: got error %v, want nil", err)
	}
	parsed, err := parseCompact(token)
	if err != nil {
		t.Fatalf("parseCompact with RFC 7515 A.2 token: got error %v, want nil", err)
	}
	if parsed.alg != "RS256" {
		t.Errorf("vector alg: got %q, want RS256", parsed.alg)
	}
	if !verifySignature(parsed, key) {
		t.Errorf("verifySignature with RFC 7515 A.2 vector: got false, want true")
	}
	// The full Verify path must refuse it on the 2011 exp claim.
	if _, err := Verify(token, key, VerifyOptions{}); !errors.Is(err, ErrExpired) {
		t.Errorf("Verify with expired vector: got error %v, want errors.Is(_, ErrExpired)", err)
	}
}

// TestRFC7515ES256Vector checks the [RFC 7515] Appendix A.3 JWS, including
// the JOSE fixed-width R || S signature form.
func TestRFC7515ES256Vector(t *testing.T) {
	t.Parallel()

	const token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
	privateJWK := []byte(`{"kty":"EC","crv":"P-256","alg":"ES256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}`)
	publicJWK := []byte(`{"kty":"EC","crv":"P-256","alg":"ES256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`)

	key, err := PublicFromJWK(publicJWK)
	if err != nil {
		t.Fatalf("PublicFromJWK with RFC 7515 A.3 key: got error %v, want nil", err)
	}
	parsed, err := parseCompact(token)
	if err != nil {
		t.Fatalf("parseCompact with RFC 7515 A.3 token: got error %v, want nil", err)
	}
	if parsed.alg != "ES256" {
		t.Errorf("vector alg: got %q, want ES256", parsed.alg)
	}
	if !verifySignature(parsed, key) {
		t.Errorf("verifySignature with RFC 7515 A.3 vector: got false, want true")
	}

	// Signing the same payload with the RFC's private key must produce a
	// token that verifies against the RFC's public key.
	priv, err := PrivateFromJWK(privateJWK)
	if err != nil {
		t.Fatalf("PrivateFromJWK with RFC 7515 A.3 key: got error %v, want nil", err)
	}
	payload, err := json.Marshal(map[string]any{"iss": "joe", "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("marshal payload: got error %v, want nil", err)
	}
	signed, err := Sign(payload, priv, SignOptions{Algorithm: "ES256"})
	if err != nil {
		t.Fatalf("Sign with RFC 7515 A.3 key: got error %v, want nil", err)
	}
	if _, err := Verify(signed, key, VerifyOptions{}); err != nil {
		t.Errorf("Verify own ES256 token with RFC public key: got error %v, want nil", err)
	}
}

func TestVerifyWithJWKRoundTrip(t *testing.T) {
	t.Parallel()

	k1Priv, _, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: got error %v, want nil", err)
	}
	edPriv, edPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate Ed25519 key: got error %v, want nil", err)
	}
	jwk, err := ToJWK(edPub)
	if err != nil {
		t.Fatalf("ToJWK: got error %v, want nil", err)
	}
	payload := validClaims(t)
	token, err := Sign(payload, edPriv, SignOptions{Algorithm: "EdDSA", Headers: map[string]any{"kid": "key-1"}})
	if err != nil {
		t.Fatalf("Sign with kid header: got error %v, want nil", err)
	}
	got, err := VerifyWithJWK(token, jwk, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyWithJWK: got error %v, want nil", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload via VerifyWithJWK: got %q, want %q", got, payload)
	}

	// A JWK for a different key must not verify the token.
	otherJWK, err := ToJWK(k1Priv.Public())
	if err != nil {
		t.Fatalf("ToJWK for secp256k1: got error %v, want nil", err)
	}
	if _, err := VerifyWithJWK(token, otherJWK, VerifyOptions{}); !errors.Is(err, ErrAlgMismatch) {
		t.Errorf("VerifyWithJWK with wrong key: got error %v, want errors.Is(_, ErrAlgMismatch)", err)
	}
}

func TestAudienceForms(t *testing.T) {
	t.Parallel()

	edPriv, edPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate Ed25519 key: got error %v, want nil", err)
	}

	tests := []struct {
		name string
		aud  any
		want bool
	}{
		{name: "string audience matches", aud: "reader", want: true},
		{name: "array audience contains match", aud: []string{"writer", "reader"}, want: true},
		{name: "array audience without match", aud: []string{"writer"}, want: false},
		{name: "numeric audience", aud: 42, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			payload, err := json.Marshal(map[string]any{"aud": tt.aud, "exp": time.Now().Add(time.Hour).Unix()})
			if err != nil {
				t.Fatalf("marshal payload: got error %v, want nil", err)
			}
			token, err := Sign(payload, edPriv, SignOptions{Algorithm: "EdDSA"})
			if err != nil {
				t.Fatalf("Sign: got error %v, want nil", err)
			}
			_, err = Verify(token, edPub, VerifyOptions{ExpectedAudience: []string{"reader"}})
			if tt.want && err != nil {
				t.Errorf("Verify %s: got error %v, want nil", tt.name, err)
			}
			if !tt.want && !errors.Is(err, ErrAudienceMismatch) {
				t.Errorf("Verify %s: got error %v, want errors.Is(_, ErrAudienceMismatch)", tt.name, err)
			}
		})
	}
}

// verifySignature dispatches signature verification through the
// signature package, applying the JOSE fixed-width to DER conversion
// for ECDSA. This is the test-only replacement for the deleted
// verifyWithKey function.
func verifySignature(parsed *parsedJWS, key crypto.PublicKey) bool {
	alg, err := signature.AlgorithmForPublicKey(key)
	if err != nil {
		return false
	}
	sig := parsed.signature
	if size := ecdsaSize(alg); size > 0 {
		der, err := fixedToDer(parsed.signature, size)
		if err != nil {
			return false
		}
		sig = der
	}
	valid, err := signature.Verify(alg, key, sig, []byte(parsed.signingInput))
	return err == nil && valid
}
