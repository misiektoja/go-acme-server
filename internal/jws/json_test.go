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

// Enforces exact struct member names without restricting unknown member values.
func TestUnmarshalStrictMemberNames(t *testing.T) {
	type embedded struct {
		KeyID string `json:"kid"`
	}
	type item struct {
		Name string `json:"name"`
	}
	type target struct {
		embedded
		Status  string `json:"status"`
		Untag   int
		Skipped int `json:"-"`
		Inner   struct {
			Value int `json:"value"`
		} `json:"inner"`
		Items  []item          `json:"items"`
		ByName map[string]item `json:"byName"`
		Raw    json.RawMessage `json:"raw"`
		Free   map[string]any  `json:"free"`
	}
	rejected := map[string]string{
		"upper case":      `{"STATUS":"x"}`,
		"case duplicate":  `{"status":"x","Status":"y"}`,
		"unicode fold":    "{\"\u017ftatus\":\"x\"}",
		"embedded field":  `{"KID":"x"}`,
		"untagged field":  `{"untag":1}`,
		"nested object":   `{"inner":{"VALUE":1}}`,
		"object in array": `{"items":[{"name":"a"},{"Name":"b"}]}`,
		"object in map":   `{"byName":{"a":{"NAME":"b"}}}`,
		"struct field":    `{"status":"x","Inner":{}}`,
		"large unknown":   `{"Status":"x","unknown":1e1000}`,
		"negative large":  `{"status":"x","Status":"y","unknown":-1e1000}`,
		"nested large":    `{"items":[{"Name":"x"}],"unknown":{"value":1e1000}}`,
		"unicode large":   `{"\u017ftatus":"x","unknown":[1e1000]}`,
	}
	for name, in := range rejected {
		t.Run(name, func(t *testing.T) {
			var v target
			err := UnmarshalStrict([]byte(in), &v)
			var jwsErr *Error
			if !errors.As(err, &jwsErr) || jwsErr.Code != CodeMalformed || !strings.Contains(jwsErr.Detail, "only in case") {
				t.Fatalf("UnmarshalStrict(%q) error = %v, want a case mismatch", in, err)
			}
		})
	}
	accepted := `{"status":"x","kid":"k","Untag":1,"skipped":2,"Skipped":3,"inner":{"value":1},` +
		`"items":[{"name":"a"}],"byName":{"A":{"name":"b"},"a":{"name":"c"}},"raw":{"ANY":1},"free":{"X":{"Y":1}},"other":[1e1000,-1e1000]}`
	var v target
	if err := UnmarshalStrict([]byte(accepted), &v); err != nil {
		t.Fatalf("UnmarshalStrict: %v", err)
	}
	if v.Status != "x" || v.KeyID != "k" || v.Untag != 1 || v.Skipped != 0 || len(v.Items) != 1 || len(v.ByName) != 2 {
		t.Fatalf("decoded %+v", v)
	}
	var p *target
	if err := UnmarshalStrict([]byte(`{"Status":"x"}`), &p); err == nil {
		t.Fatal("case mismatch accepted through a pointer")
	}
}

// Unknown values must never let a case variant mutate a known struct field.
func FuzzUnmarshalStrictMemberNames(f *testing.F) {
	for _, value := range []string{`1e1000`, `-1e1000`, `null`, `{"nested":[1e1000]}`, `"text"`} {
		f.Add([]byte(value))
	}
	f.Fuzz(func(t *testing.T, unknown []byte) {
		if !json.Valid(unknown) {
			return
		}
		data := append([]byte(`{"Status":"deactivated","unknown":`), unknown...)
		data = append(data, '}')
		var target struct {
			Status string `json:"status"`
		}
		if err := UnmarshalStrict(data, &target); err == nil || target.Status != "" {
			t.Fatalf("case variant decoded: status=%q error=%v", target.Status, err)
		}
	})
}
