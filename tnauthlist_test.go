package acmeserver

import (
	"crypto/x509/pkix"
	"encoding/base64"
	"testing"
)

// Wraps content in a DER tag, length and value using the shortest length form the tests need.
func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	switch n := len(content); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

// Returns an explicitly tagged service provider code entry.
func spcEntry(code string) []byte { return tlv(0xa0, tlv(0x16, []byte(code))) }

// Returns an explicitly tagged single telephone number entry.
func numberEntry(number string) []byte { return tlv(0xa2, tlv(0x16, []byte(number))) }

// Returns an explicitly tagged telephone number range entry.
func rangeEntry(start string, count []byte) []byte {
	body := append(tlv(0x16, []byte(start)), tlv(0x02, count)...)
	return tlv(0xa1, tlv(0x30, body))
}

// Returns a TNAuthorizationList holding the entries.
func authorityList(entries ...[]byte) []byte {
	var body []byte
	for _, entry := range entries {
		body = append(body, entry...)
	}
	return tlv(0x30, body)
}

func TestCheckTNAuthList(t *testing.T) {
	many := make([][]byte, 0, maxTNEntries+1)
	for range maxTNEntries + 1 {
		many = append(many, spcEntry("1234"))
	}
	cases := []struct {
		name string
		der  []byte
		ok   bool
	}{
		{name: "service provider code", der: authorityList(spcEntry("1234")), ok: true},
		{name: "single number", der: authorityList(numberEntry("12125551234")), ok: true},
		{name: "number with prefix characters", der: authorityList(numberEntry("*67")), ok: true},
		{name: "range", der: authorityList(rangeEntry("1212555", []byte{0x64})), ok: true},
		{name: "several entries", der: authorityList(spcEntry("1234"), numberEntry("911"),
			rangeEntry("1212555", []byte{0x02})), ok: true},
		{name: "long count", der: authorityList(rangeEntry("1212555000", []byte{0x00, 0x98, 0x96, 0x80})), ok: true},

		{name: "empty list", der: authorityList()},
		{name: "empty input", der: nil},
		{name: "trailing data", der: append(authorityList(spcEntry("1234")), 0x00)},
		{name: "not a sequence", der: tlv(0x31, spcEntry("1234"))},
		{name: "implicit tag", der: authorityList(tlv(0x80, []byte("1234")))},
		{name: "unknown choice", der: authorityList(tlv(0xa3, tlv(0x16, []byte("1234"))))},
		{name: "non-minimal length", der: []byte{0x30, 0x81, 0x08, 0xa0, 0x06, 0x16, 0x04, '1', '2', '3', '4'}},
		{name: "indefinite length", der: []byte{0x30, 0x80, 0xa0, 0x06, 0x16, 0x04, '1', '2', '3', '4', 0x00, 0x00}},
		{name: "empty code", der: authorityList(spcEntry(""))},
		{name: "code with control byte", der: authorityList(spcEntry("12\x0034"))},
		{name: "letter in number", der: authorityList(numberEntry("1212555123A"))},
		{name: "number too long", der: authorityList(numberEntry("1234567890123456"))},
		{name: "empty number", der: authorityList(numberEntry(""))},
		{name: "count below two", der: authorityList(rangeEntry("1212555", []byte{0x01}))},
		{name: "count extends the number", der: authorityList(rangeEntry("10", []byte{0x5b}))},
		{name: "range with a prefix character", der: authorityList(rangeEntry("*67", []byte{0x02}))},
		{name: "negative count", der: authorityList(rangeEntry("1212555", []byte{0xff}))},
		{name: "non-minimal count", der: authorityList(rangeEntry("1212555", []byte{0x00, 0x64}))},
		{name: "range without count", der: tlv(0x30, tlv(0xa1, tlv(0x30, tlv(0x16, []byte("1212555")))))},
		{name: "too many entries", der: authorityList(many...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkTNAuthList(tc.der)
			if tc.ok && err != nil {
				t.Fatalf("checkTNAuthList = %v, want nil", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("checkTNAuthList accepted an invalid authority list")
			}
		})
	}
}

func TestTNAuthListIdentifierNormalize(t *testing.T) {
	der := authorityList(spcEntry("1234"))
	value := base64.RawURLEncoding.EncodeToString(der)
	normalized, err := Identifier{Type: IdentifierTNAuthList, Value: value}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if normalized.Value != value || normalized.Type != IdentifierTNAuthList {
		t.Fatalf("Normalize = %v, want %v", normalized, value)
	}
	if normalized.IsWildcard() {
		t.Fatal("a TNAuthList identifier is never a wildcard")
	}
	cases := map[string]struct {
		value string
		typ   ErrorType
	}{
		"empty":          {value: "", typ: ErrorMalformed},
		"padded":         {value: base64.URLEncoding.EncodeToString(der), typ: ErrorRejectedIdentifier},
		"standard alpha": {value: base64.RawStdEncoding.EncodeToString([]byte{0xfb, 0xff, 0xfe}), typ: ErrorRejectedIdentifier},
		"not der":        {value: base64.RawURLEncoding.EncodeToString([]byte("hello")), typ: ErrorRejectedIdentifier},
		"empty list":     {value: base64.RawURLEncoding.EncodeToString(authorityList()), typ: ErrorRejectedIdentifier},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Identifier{Type: IdentifierTNAuthList, Value: tc.value}.Normalize()
			p, ok := AsProblem(err)
			if !ok || p.Type != tc.typ {
				t.Fatalf("Normalize error = %v, want %s", err, tc.typ)
			}
		})
	}
}

func TestTNAuthListExtension(t *testing.T) {
	der := authorityList(spcEntry("1234"))
	extension := pkix.Extension{Id: tnAuthListOID, Value: der}
	id, present, err := tnAuthListExtension([]pkix.Extension{extension})
	if err != nil || !present {
		t.Fatalf("tnAuthListExtension = %v, %v, %v", id, present, err)
	}
	if id.Type != IdentifierTNAuthList || id.Value != base64.RawURLEncoding.EncodeToString(der) {
		t.Fatalf("identifier = %v", id)
	}
	if _, present, err := tnAuthListExtension(nil); present || err != nil {
		t.Fatalf("tnAuthListExtension without the extension = %v, %v", present, err)
	}
	if _, _, err := tnAuthListExtension([]pkix.Extension{extension, extension}); err == nil {
		t.Fatal("a duplicate TN authorization list extension was accepted")
	}
	broken := pkix.Extension{Id: tnAuthListOID, Value: []byte("hello")}
	if _, _, err := tnAuthListExtension([]pkix.Extension{broken}); err == nil {
		t.Fatal("an invalid TN authorization list extension was accepted")
	}
}
