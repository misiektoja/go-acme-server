package jws

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Bounds the nesting of JSON documents accepted from clients.
const MaxDepth = 32

// Decodes data into v and rejects duplicate members, nesting beyond MaxDepth and
// trailing content.
func UnmarshalStrict(data []byte, v any) error {
	if err := checkJSON(data); err != nil {
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
