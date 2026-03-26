package jws

import (
	"errors"
	"strings"
	"testing"
)

func TestUnmarshalStrictAccepts(t *testing.T) {
	var v struct {
		A int            `json:"a"`
		B map[string]any `json:"b"`
	}
	in := `{"a":1,"b":{"x":[1,{"y":null}],"z":"s"},"unknown":true}`
	if err := UnmarshalStrict([]byte(in), &v); err != nil {
		t.Fatalf("UnmarshalStrict: %v", err)
	}
	if v.A != 1 || v.B["z"] != "s" {
		t.Fatalf("decoded %+v", v)
	}
	var s string
	if err := UnmarshalStrict([]byte(`"scalar"`), &s); err != nil || s != "scalar" {
		t.Fatalf("scalar: %v %q", err, s)
	}
	var nested any
	if err := UnmarshalStrict([]byte(strings.Repeat("[", MaxDepth)+strings.Repeat("]", MaxDepth)), &nested); err != nil {
		t.Fatalf("depth %d rejected: %v", MaxDepth, err)
	}
}

func TestUnmarshalStrictRejects(t *testing.T) {
	cases := map[string]string{
		"duplicate top level": `{"a":1,"a":2}`,
		"duplicate nested":    `{"a":{"b":1,"b":2}}`,
		"duplicate in array":  `[{"a":1,"a":2}]`,
		"trailing content":    `{"a":1} {"b":2}`,
		"trailing scalar":     `{"a":1} 2`,
		"too deep":            strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1),
		"too deep objects":    strings.Repeat(`{"a":`, MaxDepth+1) + "1" + strings.Repeat("}", MaxDepth+1),
		"empty":               ``,
		"whitespace":          `  `,
		"unterminated":        `{"a":1`,
		"syntax":              `{"a":}`,
		"non-string key":      `{1:2}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			var v any
			err := UnmarshalStrict([]byte(in), &v)
			var jwsErr *Error
			if !errors.As(err, &jwsErr) || jwsErr.Code != CodeMalformed {
				t.Fatalf("UnmarshalStrict(%q) error = %v, want malformed", in, err)
			}
		})
	}
}

func TestUnmarshalStrictTypeMismatch(t *testing.T) {
	var v struct {
		A int `json:"a"`
	}
	err := UnmarshalStrict([]byte(`{"a":"text"}`), &v)
	var jwsErr *Error
	if !errors.As(err, &jwsErr) || jwsErr.Code != CodeMalformed {
		t.Fatalf("type mismatch error = %v", err)
	}
}
