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
			err:  errors.New(`upload failed: Put "https://bucket.s3.amazonaws.com/k?X-Amz-Signature=abc123&X-Amz-Credential=AKIA": timeout`),
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
		{
			// The match must stop at the delimiter, not run on and eat the
			// words after it.
			name: "closing paren and the prose after it survive",
			err:  errors.New(`(see https://upload.example.com/x?t=1) for details`),
			want: `(see https://upload.example.com) for details`,
		},
		{
			name: "angle brackets survive",
			err:  errors.New(`tried <https://a.example.com/p?q=1> and failed`),
			want: `tried <https://a.example.com> and failed`,
		},
		{
			name: "backticks survive",
			err:  errors.New("use `https://b.example.com/p` instead"),
			want: "use `https://b.example.com` instead",
		},
		{
			// Square brackets delimit an IPv6 host, so excluding them from the
			// match entirely leaves an IPv6 URL — signed query and all —
			// untouched in the message.
			name: "bracketed IPv6 host is still redacted",
			err:  errors.New(`upload failed: Put "https://[2001:db8::1]/k?X-Amz-Signature=abc123": timeout`),
			want: `upload failed: Put "https://[2001:db8::1]": timeout`,
		},
		{
			name: "IPv6 host with a port is still redacted",
			err:  errors.New(`Get "https://[2001:db8::1]:8443/upload-url?id=deadbeef": no such host`),
			want: `Get "https://[2001:db8::1]:8443": no such host`,
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
