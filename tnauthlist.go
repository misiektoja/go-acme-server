package acmeserver

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// The id-pe-TNAuthList certificate extension of RFC 8226 section 9.
var tnAuthListOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 26}

// Bounds on an authority list a client may present. RFC 8226 leaves the list and the service
// provider code unbounded, so the server picks limits a certificate can carry.
const (
	maxTNAuthListBytes           = 8 << 10
	maxTNEntries                 = 512
	maxServiceProviderCodeLength = 64
	maxTelephoneNumberLength     = 15
)

// The digits and prefixes RFC 8226 allows in a telephone number.
const telephoneNumberAlphabet = "0123456789#*"

// Reports that a TN Authorization List is not acceptable.
var errTNAuthList = errors.New("acmeserver: invalid TN authorization list")

// Decodes the base64url form of a TN Authorization List and checks its DER against RFC 8226.
func normalizeTNAuthList(value string) (Identifier, error) {
	id := Identifier{Type: IdentifierTNAuthList, Value: value}
	if value == "" {
		return Identifier{}, NewProblem(ErrorMalformed, "TNAuthList identifier value is empty")
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return Identifier{}, rejected(id, "TNAuthList identifier is not unpadded base64url")
	}
	if err := checkTNAuthList(der); err != nil {
		return Identifier{}, rejected(id, "TNAuthList identifier is not a valid authority list")
	}
	return id, nil
}

// Checks a DER TNAuthorizationList. The encoding must be canonical so that one authority list has
// exactly one identifier value.
func checkTNAuthList(der []byte) error {
	if len(der) == 0 || len(der) > maxTNAuthListBytes {
		return errTNAuthList
	}
	outer := derReader{buf: der}
	body, err := outer.expect(0x30)
	if err != nil || len(outer.buf) != 0 {
		return errTNAuthList
	}
	entries := derReader{buf: body}
	count := 0
	for len(entries.buf) != 0 {
		if count++; count > maxTNEntries {
			return errTNAuthList
		}
		tag, content, err := entries.tlv()
		if err != nil {
			return err
		}
		if err := checkTNEntry(tag, content); err != nil {
			return err
		}
	}
	if count == 0 {
		return errTNAuthList
	}
	return nil
}

// Checks one alternative of the TNEntry choice. The RFC 8226 module tags explicitly, so every
// alternative wraps the tagged type in a constructed context tag.
func checkTNEntry(tag byte, content []byte) error {
	inner := derReader{buf: content}
	switch tag {
	case 0xa0:
		value, err := inner.expect(0x16)
		if err != nil || len(inner.buf) != 0 {
			return errTNAuthList
		}
		return checkServiceProviderCode(value)
	case 0xa1:
		value, err := inner.expect(0x30)
		if err != nil || len(inner.buf) != 0 {
			return errTNAuthList
		}
		return checkTelephoneNumberRange(value)
	case 0xa2:
		value, err := inner.expect(0x16)
		if err != nil || len(inner.buf) != 0 {
			return errTNAuthList
		}
		return checkTelephoneNumber(value)
	}
	return errTNAuthList
}

// Accepts a printable service provider code, which the telephone network defines rather than PKIX.
func checkServiceProviderCode(value []byte) error {
	if len(value) == 0 || len(value) > maxServiceProviderCodeLength {
		return errTNAuthList
	}
	for _, c := range value {
		if c < 0x21 || c > 0x7e {
			return errTNAuthList
		}
	}
	return nil
}

// Checks a telephone number against the RFC 8226 size and alphabet restrictions.
func checkTelephoneNumber(value []byte) error {
	if len(value) == 0 || len(value) > maxTelephoneNumberLength {
		return errTNAuthList
	}
	for _, c := range value {
		if !strings.ContainsRune(telephoneNumberAlphabet, rune(c)) {
			return errTNAuthList
		}
	}
	return nil
}

// Checks a range and the RFC 8226 rule that the count must not extend the number's length.
func checkTelephoneNumberRange(body []byte) error {
	fields := derReader{buf: body}
	start, err := fields.expect(0x16)
	if err != nil {
		return err
	}
	if err := checkTelephoneNumber(start); err != nil {
		return err
	}
	raw, err := fields.expect(0x02)
	if err != nil {
		return err
	}
	count, err := derInteger(raw)
	if err != nil || count < 2 {
		return errTNAuthList
	}
	// The extension marker of TelephoneNumberRange admits later fields, which must still be DER.
	for len(fields.buf) != 0 {
		if _, _, err := fields.tlv(); err != nil {
			return err
		}
	}
	if strings.ContainsAny(string(start), "#*") {
		return nil
	}
	limit := int64(1)
	for range start {
		limit *= 10
	}
	first, err := strconv.ParseInt(string(start), 10, 64)
	if err != nil || count >= limit || first+count >= limit {
		return errTNAuthList
	}
	return nil
}

// Reads a canonical DER INTEGER that fits in an int64 and is not negative.
func derInteger(raw []byte) (int64, error) {
	if len(raw) == 0 || len(raw) > 8 || raw[0]&0x80 != 0 {
		return 0, errTNAuthList
	}
	if len(raw) > 1 && raw[0] == 0 && raw[1]&0x80 == 0 {
		return 0, errTNAuthList
	}
	value := int64(0)
	for _, b := range raw {
		value = value<<8 | int64(b)
	}
	return value, nil
}

// A cursor over a canonical DER encoding.
type derReader struct{ buf []byte }

// Reads the next value and returns its contents when the tag is the expected one.
func (r *derReader) expect(tag byte) ([]byte, error) {
	got, content, err := r.tlv()
	if err != nil {
		return nil, err
	}
	if got != tag {
		return nil, errTNAuthList
	}
	return content, nil
}

// Reads one tag, length and value, rejecting the forms DER does not allow.
func (r *derReader) tlv() (byte, []byte, error) {
	if len(r.buf) < 2 {
		return 0, nil, errTNAuthList
	}
	tag := r.buf[0]
	if tag&0x1f == 0x1f {
		return 0, nil, errTNAuthList
	}
	size, rest := int(r.buf[1]), r.buf[2:]
	if size&0x80 != 0 {
		octets := size & 0x7f
		if octets == 0 || octets > 4 || len(rest) < octets || rest[0] == 0 {
			return 0, nil, errTNAuthList
		}
		size = 0
		for _, b := range rest[:octets] {
			size = size<<8 | int(b)
		}
		if size < 0x80 {
			return 0, nil, errTNAuthList
		}
		rest = rest[octets:]
	}
	if len(rest) < size {
		return 0, nil, errTNAuthList
	}
	r.buf = rest[size:]
	return tag, rest[:size], nil
}

// Returns the TNAuthList identifier an extension list carries, if any.
func tnAuthListExtension(extensions []pkix.Extension) (Identifier, bool, error) {
	var found *pkix.Extension
	for i, extension := range extensions {
		if !extension.Id.Equal(tnAuthListOID) {
			continue
		}
		if found != nil {
			return Identifier{}, false, errors.New("duplicate TN authorization list extension")
		}
		found = &extensions[i]
	}
	if found == nil {
		return Identifier{}, false, nil
	}
	if err := checkTNAuthList(found.Value); err != nil {
		return Identifier{}, false, err
	}
	return Identifier{Type: IdentifierTNAuthList,
		Value: base64.RawURLEncoding.EncodeToString(found.Value)}, true, nil
}
