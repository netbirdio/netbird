package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateBundleUploadURL covers the sanity check applied to a
// management-supplied upload URL before a remote debug bundle is generated.
func TestValidateBundleUploadURL(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "empty falls back to default", raw: ""},
		{name: "https with host", raw: "https://upload.debug.netbird.io/upload"},
		{name: "https self-hosted host", raw: "https://upload.example.com"},
		{name: "plaintext rejected", raw: "http://upload.example.com", wantErr: true},
		{name: "missing host rejected", raw: "https:///upload", wantErr: true},
		{name: "port-only authority rejected", raw: "https://:443", wantErr: true},
		{name: "non-url scheme rejected", raw: "ftp://upload.example.com", wantErr: true},
		{name: "garbage rejected", raw: "://not a url", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBundleUploadURL(tc.raw)
			if tc.wantErr {
				require.Error(t, err, "an invalid upload URL must be rejected")
				return
			}
			assert.NoError(t, err, "a valid or empty upload URL must be accepted")
		})
	}
}
