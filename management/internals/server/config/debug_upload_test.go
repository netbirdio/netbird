package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebugUploadValidate(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{name: "unset publishes no destination", url: ""},
		{name: "https accepted", url: "https://upload.example.com/upload-url"},
		{name: "https with port accepted", url: "https://upload.example.com:8443/upload-url"},
		// The client fetches an upload URL from this endpoint and then PUTs the
		// bundle to whatever comes back, so a plaintext hop intercepts both.
		{name: "http refused", url: "http://upload.example.com/upload-url", wantErr: "must use https"},
		{name: "scheme-less refused", url: "upload.example.com/upload-url", wantErr: "must use https"},
		{name: "host-less refused", url: "https:///upload-url", wantErr: "must have a host"},
		{name: "unparsable refused", url: "https://upload.example.com:port", wantErr: "parse debug upload URL"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := DebugUpload{URL: tc.url}.Validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
