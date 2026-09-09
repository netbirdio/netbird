package debug

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/upload-server/types"
)

func TestResolveUploadURL(t *testing.T) {
	const (
		operatorURL  = "https://upload.example.com/upload-url"
		requestedURL = "https://requested.example.com/upload-url"
	)

	tests := []struct {
		name      string
		requested string
		published string
		want      string
	}{
		{
			name:      "requested wins over published",
			requested: requestedURL,
			published: operatorURL,
			want:      requestedURL,
		},
		{
			name:      "requested wins with nothing published",
			requested: requestedURL,
			want:      requestedURL,
		},
		{
			name:      "published used when nothing requested",
			published: operatorURL,
			want:      operatorURL,
		},
		{
			// The default stays the service NetBird runs whatever the
			// deployment: an operator who wants the bundles elsewhere says so,
			// and until then collecting one and sending it to support works.
			name: "nothing configured falls back to the NetBird service",
			want: types.DefaultBundleURL,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ResolveUploadURL(tc.requested, tc.published))
		})
	}
}
