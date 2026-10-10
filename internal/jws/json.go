package jws

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"strings"
)

// Bounds the nesting of JSON documents accepted from clients.
const MaxDepth = 32

// Decodes data into v and rejects duplicate members, nesting beyond MaxDepth, trailing content and
// member names that match a struct field only when case is ignored.
func UnmarshalStrict(data []byte, v any) error {
	if err := checkJSON(data); err != nil {
		return err
	}
	if err := checkMemberNames(data, reflect.TypeOf(v)); err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return &Error{Code: CodeMalformed, Detail: "invalid JSON: " + err.Error()}
	}
	return nil
}

// Tracks one open object or array during the structural pass.
type jsonFrame struct {
	object    bool
	keys      map[string]struct{}
	expectKey bool
}

// Walks the token stream once to enforce the structural limits UnmarshalStrict promises.
func checkJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []*jsonFrame
	values := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return &Error{Code: CodeMalformed, Detail: "invalid JSON: " + err.Error()}
		}
		if len(stack) == 0 && values > 0 {
			return &Error{Code: CodeMalformed, Detail: "invalid JSON: content after the first value"}
		}
		var top *jsonFrame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.expectKey {
			if delim, ok := tok.(json.Delim); ok && delim == '}' {
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					values++
				}
				continue
			}
			key, ok := tok.(string)
			if !ok {
				return &Error{Code: CodeMalformed, Detail: "invalid JSON: object member name is not a string"}
			}
			if _, dup := top.keys[key]; dup {
				return &Error{Code: CodeMalformed, Detail: fmt.Sprintf("invalid JSON: duplicate member %q", key)}
			}
			top.keys[key] = struct{}{}
			top.expectKey = false
			continue
		}
		if top != nil && top.object {
			top.expectKey = true
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if len(stack) >= MaxDepth {
					return &Error{Code: CodeMalformed, Detail: fmt.Sprintf("invalid JSON: nesting exceeds %d levels", MaxDepth)}
				}
				frame := &jsonFrame{object: delim == '{', expectKey: delim == '{'}
				if frame.object {
					frame.keys = make(map[string]struct{})
				}
				stack = append(stack, frame)
				continue
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		}
		if len(stack) == 0 {
			values++
		}
	}
	if len(stack) != 0 {
		return &Error{Code: CodeMalformed, Detail: "invalid JSON: unterminated value"}
	}
	if values == 0 {
		return &Error{Code: CodeMalformed, Detail: "invalid JSON: empty document"}
	}
	return nil
}

// The interface whose implementations decode their own members.
var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// Rejects members that encoding/json would assign to a struct field only by its case-insensitive
// match. RFC 8259 member names are exact, so "Status" must neither set "status" nor shadow it.
func checkMemberNames(data []byte, t reflect.Type) error {
	if t == nil {
		return nil
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		// The decoder reports the same error with its own context.
		return nil
	}
	return checkMembers(document, t)
}

// Checks the member names of one decoded value against the type it decodes into.
func checkMembers(value any, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil
	}
	switch t.Kind() { //nolint:exhaustive // Other kinds hold no member names.
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		fields := jsonFields(t)
		for key, member := range object {
			if field, ok := fields[key]; ok {
				if err := checkMembers(member, field); err != nil {
					return err
				}
				continue
			}
			// strings.EqualFold applies the folding encoding/json uses to match member names.
			for name := range fields {
				if strings.EqualFold(key, name) {
					return &Error{Code: CodeMalformed,
						Detail: fmt.Sprintf("invalid JSON: member %q differs from %q only in case", key, name)}
				}
			}
		}
	case reflect.Map:
		if object, ok := value.(map[string]any); ok {
			for _, member := range object {
				if err := checkMembers(member, t.Elem()); err != nil {
					return err
				}
			}
		}
	case reflect.Slice, reflect.Array:
		if items, ok := value.([]any); ok {
			for _, item := range items {
				if err := checkMembers(item, t.Elem()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Returns the exact JSON member names of a struct type with the type each one decodes into. It
// follows the encoding/json rules for tags, unexported fields and embedded structs, where a
// shallower field hides a deeper one with the same name.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	level := []reflect.Type{t}
	visited := map[reflect.Type]bool{}
	for len(level) > 0 {
		found := map[string]reflect.Type{}
		var next []reflect.Type
		for _, st := range level {
			if visited[st] {
				continue
			}
			visited[st] = true
			for field := range st.Fields() {
				tag := field.Tag.Get("json")
				if tag == "-" {
					continue
				}
				name, _, _ := strings.Cut(tag, ",")
				fieldType := field.Type
				if fieldType.Kind() == reflect.Pointer {
					fieldType = fieldType.Elem()
				}
				if field.Anonymous && name == "" && fieldType.Kind() == reflect.Struct {
					next = append(next, fieldType)
					continue
				}
				if !field.IsExported() {
					continue
				}
				if name == "" {
					name = field.Name
				}
				if _, hidden := fields[name]; !hidden {
					found[name] = field.Type
				}
			}
		}
		maps.Copy(fields, found)
		level = next
	}
	return fields
}
