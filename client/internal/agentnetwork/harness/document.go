package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// codec reads and writes one config format as a tree of maps. encode gets
// the file's original bytes too, so a format can edit them in place instead
// of re-encoding. A new format is a new entry in codecs.
type codec struct {
	decode func([]byte) (map[string]any, error)
	encode func(orig []byte, doc map[string]any) ([]byte, error)
}

var codecs = map[Format]codec{
	FormatJSON: {decode: decodeJSONDoc, encode: func(_ []byte, doc map[string]any) ([]byte, error) { return encodeJSONDoc(doc) }},
	FormatTOML: {decode: decodeTOMLDoc, encode: encodeTOMLDoc},
}

func codecFor(f Format) codec {
	c, ok := codecs[f]
	if !ok {
		return codec{
			decode: func([]byte) (map[string]any, error) { return nil, fmt.Errorf("unsupported format %q", f) },
			encode: func([]byte, map[string]any) ([]byte, error) { return nil, fmt.Errorf("unsupported format %q", f) },
		}
	}
	return c
}

// decodeJSONDoc parses strict JSON, keeping numbers as written. An empty
// file is an empty object.
func decodeJSONDoc(data []byte) (map[string]any, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]any{}, nil
	}
	var doc map[string]any
	if err := decodeValue(data, &doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, errors.New("top level is not an object")
	}
	return doc, nil
}

// encodeJSONDoc writes 2-space indented JSON.
// ponytail: object keys come out sorted, not in the file's order; an
// order-preserving decoder is the upgrade if users mind the reshuffle.
func encodeJSONDoc(doc map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeValue decodes exactly one JSON value, rejecting trailing data.
func decodeValue(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the top-level value")
	}
	return nil
}

// canonical is the encoding values are compared and recorded in.
func canonical(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// getPath returns the canonical value at p and whether it is present.
func getPath(doc map[string]any, p []string) (json.RawMessage, bool, error) {
	cur := doc
	for i, k := range p {
		v, ok := cur[k]
		if !ok {
			return nil, false, nil
		}
		if i == len(p)-1 {
			raw, err := canonical(v)
			return raw, true, err
		}
		next, ok := v.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("%s is not an object", PathString(p[:i+1]))
		}
		cur = next
	}
	return nil, false, nil
}

// setPath writes v at p, creating missing objects on the way.
func setPath(doc map[string]any, p []string, v any) error {
	cur := doc
	for i, k := range p[:len(p)-1] {
		next, ok := cur[k]
		if !ok {
			m := map[string]any{}
			cur[k] = m
			cur = m
			continue
		}
		m, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("%s is not an object", PathString(p[:i+1]))
		}
		cur = m
	}
	cur[p[len(p)-1]] = v
	return nil
}

// deletePath removes the key at p and any object it leaves empty.
func deletePath(doc map[string]any, p []string) {
	if len(p) == 0 {
		return
	}
	if len(p) == 1 {
		delete(doc, p[0])
		return
	}
	child, ok := doc[p[0]].(map[string]any)
	if !ok {
		return
	}
	deletePath(child, p[1:])
	if len(child) == 0 {
		delete(doc, p[0])
	}
}
