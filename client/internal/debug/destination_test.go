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

	const mdmURL = "https://mdm.example.com/upload-url"

	tests := []struct {
		name      string
		mdm       string
		requested string
		published string
		want      string
	}{
		{
			// Pinning the destination on a managed device is pointless if the
			// person at the keyboard can name another one.
			name:      "MDM outranks a URL the caller named",
			mdm:       mdmURL,
			requested: requestedURL,
			published: operatorURL,
			want:      mdmURL,
		},
		{
			name: "MDM alone wins",
			mdm:  mdmURL,
			want: mdmURL,
		},
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
			assert.Equal(t, tc.want, ResolveUploadURL(tc.mdm, tc.requested, tc.published))
		})
	}
}
