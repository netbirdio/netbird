// Package secretpayload encodes and decodes multi-field DNS-01
// credential secrets as JSON. The on-disk schema continues to store a
// single string per credential record (encrypted via crypt.FieldEncrypt);
// this layer marshals the per-provider field map into that string and
// back.
//
// A backward-compatibility fallback decodes Slice A's plain-string
// Cloudflare credentials by treating any non-JSON payload as
// {"_legacy": <whole string>} so that adapters can opt into a
// legacy-fallback read path.
package secretpayload

import (
	"encoding/json"
	"fmt"
)

// LegacyKey is the key under which Slice A's plain-string secrets are
// surfaced after Decode. Provider adapters that pre-existed Wave 4
// (only Cloudflare today) read this key as a fallback when their
// modern keys are absent, so credentials stored before Wave 4 keep
// working without a migration.
const LegacyKey = "_legacy"

// Encode marshals fields into a JSON string. Returns an error if fields
// is empty (the caller should validate provider-specific required
// fields before calling Encode).
func Encode(fields map[string]string) (string, error) {
	if len(fields) == 0 {
		return "", fmt.Errorf("empty secret payload")
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return "", fmt.Errorf("marshal secret payload: %w", err)
	}
	return string(b), nil
}

// Decode parses a payload produced by Encode. If the payload is not
// valid JSON, it is treated as a legacy plain-string secret and
// returned as map[LegacyKey]<payload>. The caller (provider adapter)
// is responsible for interpreting LegacyKey correctly.
func Decode(payload string) (map[string]string, error) {
	if payload == "" {
		return nil, fmt.Errorf("empty payload")
	}
	var fields map[string]string
	if err := json.Unmarshal([]byte(payload), &fields); err == nil {
		if len(fields) == 0 {
			return nil, fmt.Errorf("decoded payload contains no fields")
		}
		return fields, nil
	}
	// Legacy fallback: treat the whole payload as a single secret value.
	return map[string]string{LegacyKey: payload}, nil
}
