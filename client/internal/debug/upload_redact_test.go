package debug

import (
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactURLsInError(t *testing.T) {
	sentinel := errors.New("boom")

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil stays nil"},
		{
			name: "no URL is left alone",
			err:  errors.New("file too large"),
			want: "file too large",
		},
		{
			// What a failed GET actually looks like: *url.Error prints the URL
			// whole, query included.
			name: "service URL loses its query",
			err: fmt.Errorf("get presigned URL: %w", &url.Error{
				Op:  "Get",
				URL: "https://upload.example.com/upload-url?id=deadbeef",
				Err: errors.New("no such host"),
			}),
			want: `get presigned URL: Get "https://upload.example.com": no such host`,
		},
		{
			// The presigned PUT URL is the one that carries credentials.
			name: "presigned URL loses its credentials",
			err: errors.New(`upload failed: Put "https://bucket.s3.amazonaws.com/k?X-Amz-Signature=abc123&X-Amz-Credential=AKIA": timeout`),
			want: `upload failed: Put "https://bucket.s3.amazonaws.com": timeout`,
		},
		{
			name: "userinfo does not survive",
			err:  errors.New(`Get "https://user:hunter2@upload.example.com/upload-url": refused`),
			want: `Get "https://upload.example.com": refused`,
		},
		{
			name: "two URLs are both cut",
			err:  errors.New(`redirect from https://a.example.com/x?t=1 to https://b.example.com/y?t=2`),
			want: `redirect from https://a.example.com to https://b.example.com`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redactURLsInError(tc.err)
			if tc.err == nil {
				assert.NoError(t, got)
				return
			}
			require.Error(t, got)
			assert.Equal(t, tc.want, got.Error())
		})
	}

	t.Run("the original error stays reachable", func(t *testing.T) {
		wrapped := fmt.Errorf(`Get "https://upload.example.com/x?t=1": %w`, sentinel)
		assert.ErrorIs(t, redactURLsInError(wrapped), sentinel)
	})
}
