package debug

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/upload-server/types"
)

func TestResolveUploadURL(t *testing.T) {
	const (
		cloudMgm      = "https://api.netbird.io:443"
		selfHostedMgm = "https://netbird.example.com:33073"
		operatorURL   = "https://upload.example.com/upload-url"
		requestedURL  = "https://requested.example.com/upload-url"
	)

	tests := []struct {
		name          string
		requested     string
		published     string
		managementURL string
		want          string
		wantErr       bool
	}{
		{
			name:          "requested wins over published",
			requested:     requestedURL,
			published:     operatorURL,
			managementURL: selfHostedMgm,
			want:          requestedURL,
		},
		{
			name:          "requested wins on cloud too",
			requested:     requestedURL,
			managementURL: cloudMgm,
			want:          requestedURL,
		},
		{
			name:          "published used when nothing requested",
			published:     operatorURL,
			managementURL: selfHostedMgm,
			want:          operatorURL,
		},
		{
			// A cloud deployment publishing its own destination must not be
			// overridden by the compiled-in default.
			name:          "published wins over the cloud fallback",
			published:     operatorURL,
			managementURL: cloudMgm,
			want:          operatorURL,
		},
		{
			name:          "cloud falls back to the NetBird service",
			managementURL: cloudMgm,
			want:          types.DefaultBundleURL,
		},
		{
			// The whole point of GHSA-hf99-43rj-h577: no silent hop to a
			// vendor-controlled destination.
			name:          "self-hosted with no destination fails closed",
			managementURL: selfHostedMgm,
			wantErr:       true,
		},
		{
			name:          "unknown management URL fails closed",
			managementURL: "",
			wantErr:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveUploadURL(tc.requested, tc.published, tc.managementURL)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrNoUploadDestination)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
