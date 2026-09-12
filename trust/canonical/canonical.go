package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/fxamacker/cbor/v2"

	"github.com/bperin/trust/crypto/hash"
)

// Encoding selects the canonical byte encoding produced for a value.
type Encoding int

const (
	// EncodingJSON selects the JSON Canonicalization Scheme (JCS) per
	// [RFC 8785]. This is the default encoding for trust objects.
	EncodingJSON Encoding = iota

	// EncodingCBOR selects deterministically encoded CBOR per
	// [RFC 8949] §4.2.1.
	EncodingCBOR
)

// ErrNonFiniteNumber is returned when a value contains a number that is not
// representable in the JSON data model (NaN or an infinity). [RFC 8785]
// §3.2.2.3 limits numbers to finite IEEE 754 double-precision values.
var ErrNonFiniteNumber = errors.New("canonical: non-finite number is not valid JSON data")

// ErrUnknownEncoding is returned by Marshal when the Encoding selector is not
// EncodingJSON or EncodingCBOR.
var ErrUnknownEncoding = errors.New("canonical: unknown encoding")

// EncodingDeclarer may be implemented by a trust object to declare the
// canonical encoding it uses. CanonicalHash consults this interface; values
// that do not implement it are hashed as EncodingJSON.
type EncodingDeclarer interface {
	// CanonicalEncoding returns the canonical encoding of the receiver.
	CanonicalEncoding() Encoding
}

// Marshal produces the canonical bytes of v in the encoding selected by enc.
// It dispatches to JSONCanonicalize for EncodingJSON and to CBOREncode for
// EncodingCBOR; any other selector returns ErrUnknownEncoding.
func Marshal(v interface{}, enc Encoding) ([]byte, error) {
	switch enc {
	case EncodingJSON:
		return JSONCanonicalize(v)
	case EncodingCBOR:
		return CBOREncode(v)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownEncoding, enc)
	}
}

// JSONCanonicalize implements [RFC 8785] — the JSON Canonicalization Scheme.
// It marshals v to JSON, decodes the result into the JSON data model
// (objects, arrays, strings, IEEE 754 double-precision numbers, true, false,
// null), and re-serializes it canonically: object property names sorted by
// UTF-16 code unit, numbers in ECMAScript Number::toString shortest
// round-trip form, and no insignificant whitespace.
//
// Numbers outside the IEEE 754 double-precision range (or Go values such as
// math.Inf and math.NaN, which encoding/json rejects) cause an error.
func JSONCanonicalize(v interface{}) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: marshal JSON: %w", err)
	}
	var tree interface{}
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("canonical: decode JSON: %w", err)
	}
	var buf bytes.Buffer
	if err := appendJCS(&buf, tree); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// detCBORMode is the deterministic CBOR encoding mode per [RFC 8949] §4.2.1,
// built once at package initialization. cbor.EncMode is immutable and safe
// for concurrent use, so this is shared state but not mutable state.
var detCBORMode = mustDetCBORMode()

// mustDetCBORMode builds the deterministic encoding mode. EncMode only fails
// on invalid option combinations; CoreDetEncOptions is fixed, so a failure
// here is a library bug and panics.
func mustDetCBORMode() cbor.EncMode {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic("canonical: cbor.CoreDetEncOptions().EncMode(): " + err.Error())
	}
	return em
}

// CBOREncode implements [RFC 8949] §4.2.1 — deterministically encoded CBOR.
// Integers and length arguments use shortest form, items are definite-length,
// and map keys are sorted bytewise lexicographic on their encoded form. The
// same logical value always produces the same bytes regardless of Go map
// iteration order.
func CBOREncode(v interface{}) ([]byte, error) {
	b, err := detCBORMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: encode CBOR: %w", err)
	}
	return b, nil
}

// CanonicalHash returns the [FIPS 180-4] SHA-256 digest of the canonical
// bytes of v. The encoding is EncodingCBOR when v implements EncodingDeclarer
// and declares it, and EncodingJSON otherwise. The digest is the identity of
// the trust object: identical canonical bytes yield an identical hash.
func CanonicalHash(v interface{}) ([32]byte, error) {
	enc := EncodingJSON
	if d, ok := v.(EncodingDeclarer); ok {
		enc = d.CanonicalEncoding()
	}
	b, err := Marshal(v, enc)
	if err != nil {
		return [32]byte{}, err
	}
	return hash.NewSHA256().Sum(b), nil
}

// appendJCS serializes a decoded JSON value per [RFC 8785] §3.2.2.
func appendJCS(buf *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		return appendJCSNumber(buf, t)
	case string:
		appendJCSString(buf, t)
	case []interface{}:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendJCS(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// [RFC 8785] §3.2.3: property names are sorted on their UTF-16
		// code units, matching the ECMAScript sort order.
		sort.Slice(keys, func(i, j int) bool { return jcsKeyLess(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			appendJCSString(buf, k)
			buf.WriteByte(':')
			if err := appendJCS(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported JSON type %T", v)
	}
	return nil
}

// jcsKeyLess compares two property names by UTF-16 code unit per [RFC 8785]
// §3.2.3. For strings without supplementary-plane characters (>= U+10000),
// UTF-16 order coincides with code point order and therefore with Go's
// byte-wise string order, so the UTF-16 expansion only runs when needed.
func jcsKeyLess(a, b string) bool {
	if !hasSupplementary(a) && !hasSupplementary(b) {
		return a < b
	}
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// hasSupplementary reports whether s contains a code point outside the Basic
// Multilingual Plane, which encodes as a UTF-16 surrogate pair.
func hasSupplementary(s string) bool {
	for _, r := range s {
		if r >= 0x10000 {
			return true
		}
	}
	return false
}

// appendJCSString serializes s as a JSON string per [RFC 8785] §3.2.2.2:
// only the mandatory escapes are applied — quotation mark, reverse solidus,
// the short escapes \b \f \n \r \t, and \u00xx for the remaining control
// characters. All other characters are emitted as raw UTF-8.
func appendJCSString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// appendJCSNumber serializes f per [RFC 8785] §3.2.2.3, which adopts the
// ECMAScript Number::toString algorithm: shortest round-trip digits, plain
// decimal notation for exponents in a fixed window, and scientific notation
// outside it. Non-finite values are rejected per ErrNonFiniteNumber.
func appendJCSNumber(buf *bytes.Buffer, f float64) error {
	switch {
	case math.IsNaN(f) || math.IsInf(f, 0):
		return ErrNonFiniteNumber
	case f == 0: // also covers -0; ECMAScript ToString(-0) is "0".
		buf.WriteByte('0')
		return nil
	}
	if math.Signbit(f) {
		buf.WriteByte('-')
		f = -f
	}
	// FormatFloat with verb 'e' and precision -1 yields the shortest digit
	// string that round-trips to f — the same digits ECMAScript produces.
	s := strconv.FormatFloat(f, 'e', -1, 64)
	ePos := strings.IndexByte(s, 'e')
	exp, err := strconv.Atoi(s[ePos+1:])
	if err != nil {
		return fmt.Errorf("canonical: parse exponent %q: %w", s, err)
	}
	digits := strings.Replace(s[:ePos], ".", "", 1)
	k := len(digits) // significant digit count
	n := exp + 1     // value = 0.digits * 10^n in ECMAScript's k/n framing
	switch {
	case k <= n && n <= 21:
		// Integer: digits followed by zeros.
		buf.WriteString(digits)
		writeZeros(buf, n-k)
	case 0 < n && n <= 21:
		// Decimal point inside the digit string.
		buf.WriteString(digits[:n])
		buf.WriteByte('.')
		buf.WriteString(digits[n:])
	case -6 < n && n <= 0:
		// Leading "0." followed by zeros then digits.
		buf.WriteString("0.")
		writeZeros(buf, -n)
		buf.WriteString(digits)
	default:
		// Scientific notation: d[.ddd]e±(n-1).
		buf.WriteByte(digits[0])
		if k > 1 {
			buf.WriteByte('.')
			buf.WriteString(digits[1:])
		}
		buf.WriteByte('e')
		m := n - 1
		if m >= 0 {
			buf.WriteByte('+')
		} else {
			buf.WriteByte('-')
			m = -m
		}
		buf.WriteString(strconv.Itoa(m))
	}
	return nil
}

// writeZeros appends n ASCII '0' bytes to buf.
func writeZeros(buf *bytes.Buffer, n int) {
	for i := 0; i < n; i++ {
		buf.WriteByte('0')
	}
}
