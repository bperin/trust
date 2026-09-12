package canonical

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// mustDecodeJSON decodes a JSON document into the generic tree
// (map[string]interface{}, []interface{}, float64, string, bool, nil) that
// JSONCanonicalize consumes after its own marshal/decode round-trip.
func mustDecodeJSON(t *testing.T, doc string) interface{} {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatalf("invalid test input JSON: %v", err)
	}
	return v
}

func TestJSONCanonicalize_RFC8785Vectors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// Vector: [RFC 8785] §3.1 — canonicalization example. The
			// input uses unsorted keys, non-shortest numbers, and
			// escape sequences that must be normalized.
			name: "RFC 8785 §3.1 example",
			in: `{
				"numbers": [333333333.33333329, 1E30, 4.50,
				            2e-3, 0.000000000000000000000000001],
				"string": "\u20ac$\u000F\na'\u0042\"\\\"\u005c/",
				"literals": [null, true, false]
			}`,
			want: `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\na'B\"\\\"\\/"}`,
		},
		{
			// Vector: JCS test data — property names sort as strings,
			// not numerically.
			name: "string keys sort lexicographically",
			in:   `{"10":"ten","2":"two","1":"one"}`,
			want: `{"1":"one","10":"ten","2":"two"}`,
		},
		{
			// Vector: JCS test data — '$' (U+0024) sorts before
			// '€' (U+20AC).
			name: "non-ASCII BMP keys",
			in:   `{"€":"euro","$":"dollar"}`,
			want: `{"$":"dollar","€":"euro"}`,
		},
		{
			// Vector: [RFC 8785] §3.2.3 — sort is on UTF-16 code units.
			// "😀" (U+1F600) encodes as surrogate pair D83D DE00, and
			// 0xD83D < 0xFFFD, so it sorts before U+FFFD even though
			// U+FFFD < U+1F600 in code point order.
			name: "supplementary-plane key sorts by UTF-16",
			in:   `{"�":1,"😀":2}`,
			want: `{"😀":2,"�":1}`,
		},
		{
			// Vector: [RFC 8785] §3.2.2.2 — control characters use
			// short escapes where defined, \u00xx (lowercase) otherwise.
			name: "string escapes",
			in:   `{"s":"\u0001\u001f\b\f\t\"\\"}`,
			want: `{"s":"\u0001\u001f\b\f\t\"\\"}`,
		},
		{
			// Empty object and array stay empty.
			name: "empty object",
			in:   `{}`,
			want: `{}`,
		},
		{
			name: "empty array",
			in:   `[]`,
			want: `[]`,
		},
		{
			name: "nested empty",
			in:   `{"a":[],"b":{}}`,
			want: `{"a":[],"b":{}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JSONCanonicalize(mustDecodeJSON(t, tt.in))
			if err != nil {
				t.Fatalf("JSONCanonicalize() error = %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("JSONCanonicalize()\n got = %s\nwant = %s", got, tt.want)
			}
		})
	}
}

func TestJSONCanonicalize_Numbers(t *testing.T) {
	// Vector: [RFC 8785] §3.2.2.3 — numbers serialize per ECMAScript
	// Number::toString: shortest round-trip digits, plain notation for
	// 1e-6 <= |v| < 1e21, scientific outside that window.
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "zero", in: `0`, want: `0`},
		{name: "negative zero", in: `-0`, want: `0`},
		{name: "one", in: `1`, want: `1`},
		{name: "negative one", in: `-1`, want: `-1`},
		{name: "fraction", in: `0.1`, want: `0.1`},
		{name: "trailing zeros dropped", in: `4.50`, want: `4.5`},
		{name: "integer exponent to fixed", in: `1e6`, want: `1000000`},
		{name: "1e20 stays fixed", in: `1e20`, want: `100000000000000000000`},
		{name: "1e21 goes scientific", in: `1e21`, want: `1e+21`},
		{name: "1e30", in: `1E30`, want: `1e+30`},
		{name: "small fixed boundary", in: `1e-6`, want: `0.000001`},
		{name: "scientific below 1e-6", in: `1e-7`, want: `1e-7`},
		{name: "min denormal", in: `5e-324`, want: `5e-324`},
		{name: "max double", in: `1.7976931348623157e308`, want: `1.7976931348623157e+308`},
		{name: "0.1+0.2 representation", in: `0.30000000000000004`, want: `0.30000000000000004`},
		{name: "2e-3 to fixed", in: `2e-3`, want: `0.002`},
		{name: "multi-digit mantissa scientific", in: `9.99e22`, want: `9.99e+22`},
		{name: "negative scientific", in: `-1.5e-10`, want: `-1.5e-10`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JSONCanonicalize(mustDecodeJSON(t, tt.in))
			if err != nil {
				t.Fatalf("JSONCanonicalize(%s) error = %v", tt.in, err)
			}
			if string(got) != tt.want {
				t.Errorf("JSONCanonicalize(%s) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

func TestJSONCanonicalize_NonCanonicalInput(t *testing.T) {
	// Negative test: non-canonical JSON (extra whitespace, reordered keys)
	// must canonicalize to the same bytes as the minimal canonical form.
	canonical := `{"a":1,"b":[1,2,3],"c":{"x":true,"y":null}}`
	nonCanonical := `{
		"c" : {  "y": null,  "x" : true },
		"b" : [ 1,  2, 3 ],
		"a" : 1
	}`

	want, err := JSONCanonicalize(mustDecodeJSON(t, canonical))
	if err != nil {
		t.Fatalf("JSONCanonicalize(canonical) error = %v", err)
	}
	got, err := JSONCanonicalize(mustDecodeJSON(t, nonCanonical))
	if err != nil {
		t.Fatalf("JSONCanonicalize(nonCanonical) error = %v", err)
	}

	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Errorf("non-canonical input canonicalized differently:\n got = %s\nwant = %s", got, want)
	}
}

func TestJSONCanonicalize_Determinism(t *testing.T) {
	// Two documents with identical content and different key order must
	// produce byte-identical canonical output across repeated runs.
	docA := `{"a":1,"b":{"d":4,"c":3},"e":[5,6,7]}`
	docB := `{"e":[5,6,7],"b":{"c":3,"d":4},"a":1}`

	for i := 0; i < 10; i++ {
		a, err := JSONCanonicalize(mustDecodeJSON(t, docA))
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		b, err := JSONCanonicalize(mustDecodeJSON(t, docB))
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if subtle.ConstantTimeCompare(a, b) != 1 {
			t.Fatalf("run %d: key order changed output:\n a = %s\n b = %s", i, a, b)
		}
	}
}

func TestJSONCanonicalize_Errors(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
	}{
		{name: "func value", in: func() {}},
		{name: "channel", in: make(chan int)},
		{name: "positive infinity", in: math.Inf(1)},
		{name: "NaN", in: math.NaN()},
		{name: "complex", in: complex(1, 2)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := JSONCanonicalize(tt.in); err == nil {
				t.Errorf("JSONCanonicalize(%T) = nil error, want error", tt.in)
			}
		})
	}
}

func TestCBOREncode_RFC8949Vectors(t *testing.T) {
	// Vectors: [RFC 8949] Appendix A — encoded byte strings are the
	// preferred (shortest) serialization, which §4.2.1 requires.
	tests := []struct {
		name string
		in   interface{}
		want string // hex
	}{
		{name: "null", in: nil, want: "f6"},
		{name: "false", in: false, want: "f4"},
		{name: "true", in: true, want: "f5"},
		{name: "zero", in: 0, want: "00"},
		{name: "one", in: 1, want: "01"},
		{name: "ten", in: 10, want: "0a"},
		{name: "23 direct", in: 23, want: "17"},
		{name: "24 one-byte arg", in: 24, want: "1818"},
		{name: "100", in: 100, want: "1864"},
		{name: "1000", in: 1000, want: "1903e8"},
		{name: "negative one", in: -1, want: "20"},
		{name: "negative ten", in: -10, want: "29"},
		{name: "negative hundred", in: -100, want: "3863"},
		{name: "negative thousand", in: -1000, want: "3903e7"},
		{name: "empty string", in: "", want: "60"},
		{name: "a", in: "a", want: "6161"},
		{name: "IETF", in: "IETF", want: "6449455446"},
		{name: "empty bytes", in: []byte{}, want: "40"},
		{name: "bytes", in: []byte{1, 2, 3, 4}, want: "4401020304"},
		{name: "empty array", in: []interface{}{}, want: "80"},
		{name: "array 1 2 3", in: []interface{}{1, 2, 3}, want: "83010203"},
		{name: "nested array", in: []interface{}{1, []interface{}{2, 3}, []interface{}{4, 5}}, want: "8301820203820405"},
		{name: "empty map", in: map[string]interface{}{}, want: "a0"},
		{
			// Vector: [RFC 8949] Appendix A — {"a":1,"b":[2,3]}.
			name: "map a b",
			in:   map[string]interface{}{"a": 1, "b": []interface{}{2, 3}},
			want: "a26161016162820203",
		},
		{
			// Vector: [RFC 8949] §4.2.1 — map keys sort bytewise
			// lexicographic on encoded form. Encoded keys:
			// 0a(10), 1864(100), 20(-1), 617a("z"), 626161("aa"), f4(false).
			name: "deterministic key order",
			in:   map[interface{}]interface{}{10: 0, -1: 0, false: 0, 100: 0, "z": 0, "aa": 0},
			want: "a60a001864002000617a0062616100f400",
		},
		{
			// Vector: [RFC 8949] §4.2.1 — bytewise lexicographic
			// ordering. 1000 (3-byte encoding 1903e8) sorts before "z"
			// (2-byte encoding 617a) because 0x19 < 0x61 bytewise, even
			// though its encoding is longer.
			name: "bytewise order ignores encoded length",
			in:   map[interface{}]interface{}{1000: 0, "z": 0},
			want: "a21903e800617a00",
		},
		{
			// [RFC 8949] §4.2.1 prefers the shortest float form that
			// preserves the value: 1.5 fits in a half-float.
			name: "float64 1.5",
			in:   1.5,
			want: "f93e00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CBOREncode(tt.in)
			if err != nil {
				t.Fatalf("CBOREncode() error = %v", err)
			}
			want, err := hex.DecodeString(tt.want)
			if err != nil {
				t.Fatalf("invalid test vector hex: %v", err)
			}
			if subtle.ConstantTimeCompare(got, want) != 1 {
				t.Errorf("CBOREncode() = %x, want %s", got, tt.want)
			}
		})
	}
}

func TestCBOREncode_Determinism(t *testing.T) {
	// Negative test: a non-deterministic map (random Go iteration order)
	// must always emit the canonical sorted form.
	a := map[string]interface{}{"b": 2, "a": 1, "c": 3}
	b := map[string]interface{}{"c": 3, "a": 1, "b": 2}

	for i := 0; i < 10; i++ {
		ba, err := CBOREncode(a)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		bb, err := CBOREncode(b)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if subtle.ConstantTimeCompare(ba, bb) != 1 {
			t.Fatalf("run %d: map order changed output:\n a = %x\n b = %x", i, ba, bb)
		}
	}
}

func TestCBOREncode_Errors(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
	}{
		{name: "channel", in: make(chan int)},
		{name: "func value", in: func() {}},
		{name: "complex", in: complex(1, 2)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := CBOREncode(tt.in); err == nil {
				t.Errorf("CBOREncode(%T) = nil error, want error", tt.in)
			}
		})
	}
}

// cborDoc is a test helper that declares CBOR as its canonical encoding.
type cborDoc map[string]interface{}

// CanonicalEncoding implements EncodingDeclarer for cborDoc.
func (cborDoc) CanonicalEncoding() Encoding { return EncodingCBOR }

func TestMarshal_Dispatch(t *testing.T) {
	v := map[string]interface{}{"a": 1}

	j, err := Marshal(v, EncodingJSON)
	if err != nil {
		t.Fatalf("Marshal(EncodingJSON) error = %v", err)
	}
	if string(j) != `{"a":1}` {
		t.Errorf("Marshal(EncodingJSON) = %s, want %s", j, `{"a":1}`)
	}

	c, err := Marshal(v, EncodingCBOR)
	if err != nil {
		t.Fatalf("Marshal(EncodingCBOR) error = %v", err)
	}
	if hex.EncodeToString(c) != "a1616101" {
		t.Errorf("Marshal(EncodingCBOR) = %x, want a1616101", c)
	}

	if _, err := Marshal(v, Encoding(99)); !errors.Is(err, ErrUnknownEncoding) {
		t.Errorf("Marshal(unknown) error = %v, want ErrUnknownEncoding", err)
	}
}

func TestCanonicalHash_Determinism(t *testing.T) {
	v := map[string]interface{}{"issuer": "did:example:org", "seq": 7}

	h1, err := CanonicalHash(v)
	if err != nil {
		t.Fatalf("CanonicalHash() error = %v", err)
	}
	h2, err := CanonicalHash(v)
	if err != nil {
		t.Fatalf("CanonicalHash() error = %v", err)
	}
	if subtle.ConstantTimeCompare(h1[:], h2[:]) != 1 {
		t.Error("CanonicalHash not deterministic for same object")
	}

	// Hash must equal SHA-256 of the JCS canonical bytes.
	jcs, err := JSONCanonicalize(v)
	if err != nil {
		t.Fatalf("JSONCanonicalize() error = %v", err)
	}
	want := sha256.Sum256(jcs)
	if subtle.ConstantTimeCompare(h1[:], want[:]) != 1 {
		t.Errorf("CanonicalHash = %x, want SHA-256(JCS) = %x", h1, want)
	}
}

func TestCanonicalHash_EncodingDeclarer(t *testing.T) {
	// A value declaring EncodingCBOR must hash the CBOR canonical bytes,
	// not the JCS bytes.
	v := cborDoc{"a": 1}

	h, err := CanonicalHash(v)
	if err != nil {
		t.Fatalf("CanonicalHash() error = %v", err)
	}
	cborBytes, err := CBOREncode(map[string]interface{}(v))
	if err != nil {
		t.Fatalf("CBOREncode() error = %v", err)
	}
	want := sha256.Sum256(cborBytes)
	if subtle.ConstantTimeCompare(h[:], want[:]) != 1 {
		t.Errorf("CanonicalHash(CBOR) = %x, want SHA-256(CBOR) = %x", h, want)
	}
}

func TestCanonicalHash_Errors(t *testing.T) {
	if _, err := CanonicalHash(func() {}); err == nil {
		t.Error("CanonicalHash(func) = nil error, want error")
	}
}

// TestNoAuthOrChainImports enforces the dependency rule: trust/canonical
// must not import auth/ or chain/.
func TestNoAuthOrChainImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, name := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", name, err)
			}
			for _, bad := range []string{"github.com/bperin/auth", "github.com/bperin/chain"} {
				if path == bad || strings.HasPrefix(path, bad+"/") {
					t.Errorf("%s imports forbidden module %s", name, path)
				}
			}
		}
	}
}
