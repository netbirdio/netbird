package secretpayload

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := map[string]string{
		"access_key_id":     "AKIAEXAMPLE",
		"secret_access_key": "supersecret",
		"region":            "us-east-1",
	}
	encoded, err := Encode(in)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	out, err := Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestEncodeRejectsEmpty(t *testing.T) {
	_, err := Encode(nil)
	require.Error(t, err)

	_, err = Encode(map[string]string{})
	require.Error(t, err)
}

func TestDecodeLegacyPlainString(t *testing.T) {
	// Slice A stored Cloudflare tokens as plain strings (no JSON).
	const legacy = "cf_legacy_token_value"

	out, err := Decode(legacy)
	require.NoError(t, err)
	assert.Equal(t, legacy, out[LegacyKey])
	assert.Len(t, out, 1, "legacy payload should produce exactly one field")
}

func TestDecodeRejectsEmptyPayload(t *testing.T) {
	_, err := Decode("")
	require.Error(t, err)
}

func TestDecodeRejectsEmptyJSONObject(t *testing.T) {
	_, err := Decode("{}")
	require.Error(t, err)
}

func TestDecodeRejectsNonObjectJSON(t *testing.T) {
	// Arrays and other non-object JSON should fall through to the legacy
	// path (still parses as the literal string in LegacyKey).
	out, err := Decode("[1,2,3]")
	require.NoError(t, err)
	assert.Equal(t, "[1,2,3]", out[LegacyKey])
}
