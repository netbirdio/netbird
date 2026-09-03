package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// TestValidateBundleUploadURL covers the sanity check applied to a
// management-supplied upload URL before a remote debug bundle is generated.
func TestValidateBundleUploadURL(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "empty defers to the deployment destination", raw: ""},
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

// TestEngineDebugUploadURL covers the destination the management server
// publishes: the engine keeps the last value it saw so the bundle paths, which
// run off the engine loop, do not have to re-read a sync response.
func TestEngineDebugUploadURL(t *testing.T) {
	e := &Engine{}
	assert.Empty(t, e.DebugUploadURL(), "a peer that never synced publishes no destination")

	e.handleDebugUploadUpdate(nil)
	assert.Empty(t, e.DebugUploadURL(), "a management server predating the field publishes none")

	e.handleDebugUploadUpdate(&mgmProto.DebugConfig{UploadUrl: "https://upload.example.com/upload-url"})
	assert.Equal(t, "https://upload.example.com/upload-url", e.DebugUploadURL())

	// An operator that removes the destination must take it away from the peer,
	// not leave it uploading to a host that no longer exists.
	e.handleDebugUploadUpdate(&mgmProto.DebugConfig{})
	assert.Empty(t, e.DebugUploadURL())
}
