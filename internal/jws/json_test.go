package jws

import (
	"encoding/json"
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

// Checks that every accepted document is valid JSON within the nesting bound and decodes twice.
func FuzzUnmarshalStrict(f *testing.F) {
	f.Add([]byte(`{"a":1,"b":{"x":[1,{"y":null}],"z":"s"}}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1)))
	f.Add([]byte(`"scalar" 1`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v any
		err := UnmarshalStrict(data, &v)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || e.Code != CodeMalformed {
				t.Fatalf("UnmarshalStrict returned an untyped error: %v", err)
			}
			return
		}
		if !json.Valid(data) {
			t.Fatalf("accepted invalid JSON %q", data)
		}
		if depth := jsonDepth(v); depth > MaxDepth {
			t.Fatalf("accepted nesting of %d levels", depth)
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var again any
		if err := UnmarshalStrict(encoded, &again); err != nil {
			t.Fatalf("re-encoded document rejected: %v", err)
		}
	})
}

// Counts nested objects and arrays in a decoded document.
func jsonDepth(v any) int {
	switch value := v.(type) {
	case map[string]any:
		depth := 0
		for _, member := range value {
			depth = max(depth, jsonDepth(member))
		}
		return depth + 1
	case []any:
		depth := 0
		for _, element := range value {
			depth = max(depth, jsonDepth(element))
		}
		return depth + 1
	}
	return 0
}
