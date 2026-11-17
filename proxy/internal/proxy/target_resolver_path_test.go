package proxy

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAccessPath(t *testing.T) {
	tests := []struct {
		name    string
		url     url.URL
		wantErr bool
	}{
		{name: "root", url: url.URL{Path: "/"}},
		{name: "nested path", url: url.URL{Path: "/public/status"}},
		{name: "trailing slash", url: url.URL{Path: "/public/"}},
		{name: "dots within segments", url: url.URL{Path: "/.well-known/file..json"}},
		{name: "space", url: url.URL{Path: "/file name"}},
		{name: "unicode", url: url.URL{Path: "/unicode/é"}},
		{name: "encoded space", url: url.URL{Path: "/file name", RawPath: "/file%20name"}},
		{name: "encoded letter", url: url.URL{Path: "/public", RawPath: "/%70ublic"}},
		{name: "encoded unicode", url: url.URL{Path: "/unicode/é", RawPath: "/unicode/%C3%a9"}},
		{
			name: "query and fragment are separate from the path",
			url:  url.URL{Path: "/public", RawQuery: "next=/../private", Fragment: "section"},
		},
		{name: "empty path", url: url.URL{}, wantErr: true},
		{name: "relative path", url: url.URL{Path: "public"}, wantErr: true},
		{name: "opaque URL", url: url.URL{Path: "/public", Opaque: "//example.com/private"}, wantErr: true},
		{name: "invalid UTF-8", url: url.URL{Path: "/public/\xff"}, wantErr: true},
		{
			name:    "encoded invalid UTF-8",
			url:     url.URL{Path: "/public/\xff", RawPath: "/public/%ff"},
			wantErr: true,
		},
		{name: "bare escape", url: url.URL{Path: "/public", RawPath: "/public%"}, wantErr: true},
		{name: "short escape", url: url.URL{Path: "/public", RawPath: "/public%2"}, wantErr: true},
		{name: "invalid escape", url: url.URL{Path: "/public", RawPath: "/public%GG"}, wantErr: true},
		{name: "mismatched raw path", url: url.URL{Path: "/public", RawPath: "/private"}, wantErr: true},
		{name: "duplicate separator", url: url.URL{Path: "/public//private"}, wantErr: true},
		{name: "backslash", url: url.URL{Path: "/public\\private"}, wantErr: true},
		{name: "path parameter", url: url.URL{Path: "/public;private"}, wantErr: true},
		{name: "query delimiter in path", url: url.URL{Path: "/public?private"}, wantErr: true},
		{name: "fragment delimiter in path", url: url.URL{Path: "/public#private"}, wantErr: true},
		{name: "dot segment", url: url.URL{Path: "/public/./private"}, wantErr: true},
		{name: "parent segment", url: url.URL{Path: "/public/../private"}, wantErr: true},
		{name: "NUL", url: url.URL{Path: "/public/\x00private"}, wantErr: true},
		{name: "control character", url: url.URL{Path: "/public/\x1fprivate"}, wantErr: true},
		{name: "DEL", url: url.URL{Path: "/public/\x7fprivate"}, wantErr: true},
		{
			name:    "encoded separator",
			url:     url.URL{Path: "/public/private", RawPath: "/public%2Fprivate"},
			wantErr: true,
		},
		{
			// The decoded dot is within a segment, so only escaped validation rejects it.
			name:    "encoded dot within segment",
			url:     url.URL{Path: "/file.txt", RawPath: "/file%2Etxt"},
			wantErr: true,
		},
		{
			name:    "double encoding",
			url:     url.URL{Path: "/public/%2e%2e/private", RawPath: "/public/%252e%252e/private"},
			wantErr: true,
		},
		{name: "percent without raw path", url: url.URL{Path: "/public/%2fprivate"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAccessPath(&tt.url)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrUnsafeRequestPath, "unsafe URL path must be rejected")
				return
			}
			assert.NoError(t, err, "ordinary URL path must remain supported")
		})
	}
}

func TestValidateAccessPath_RejectsEncodedTraversal(t *testing.T) {
	tests := []struct {
		name    string
		rawPath string
	}{
		{name: "encoded parent segment", rawPath: "/public/%2E%2E/private"},
		{
			name: "UTF-16LE encoded traversal",
			rawPath: "%2f%00%70%00%75%00%62%00%6c%00%69%00%63%00%2f%00" +
				"%2e%00%2e%00%2f%00%70%00%72%00%69%00%76%00%61%00%74%00%65%00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Preserve percent-decoded bytes, including NULs, without transcoding UTF-16.
			path, err := url.PathUnescape(tt.rawPath)
			require.NoError(t, err)

			err = validateAccessPath(&url.URL{Path: path, RawPath: tt.rawPath})
			assert.ErrorIs(t, err, ErrUnsafeRequestPath, "encoded traversal must be rejected")
		})
	}
}

func TestValidateDecodedAccessPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "root", path: "/"},
		{name: "nested path", path: "/public/status"},
		{name: "trailing slash", path: "/public/"},
		{name: "dots within segments", path: "/.well-known/file..json/..."},
		{name: "space boundary", path: "/file\x20name"},
		{name: "last printable ASCII", path: "/file\x7e"},
		{name: "unicode", path: "/unicode/é"},
		{name: "duplicate leading separator", path: "//public", wantErr: true},
		{name: "duplicate nested separator", path: "/public//private", wantErr: true},
		{name: "backslash", path: "/public\\private", wantErr: true},
		{name: "path parameter", path: "/public;private", wantErr: true},
		{name: "query delimiter", path: "/public?private", wantErr: true},
		{name: "fragment delimiter", path: "/public#private", wantErr: true},
		{name: "dot segment", path: "/public/./private", wantErr: true},
		{name: "parent segment", path: "/public/../private", wantErr: true},
		{name: "terminal dot segment", path: "/public/.", wantErr: true},
		{name: "terminal parent segment", path: "/public/..", wantErr: true},
		{name: "NUL", path: "/public/\x00private", wantErr: true},
		{name: "tab", path: "/public/\tprivate", wantErr: true},
		{name: "newline", path: "/public/\nprivate", wantErr: true},
		{name: "carriage return", path: "/public/\rprivate", wantErr: true},
		{name: "last C0 control", path: "/public/\x1fprivate", wantErr: true},
		{name: "DEL", path: "/public/\x7fprivate", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDecodedAccessPath(tt.path)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrUnsafeRequestPath, "unsafe decoded path %q must be rejected", tt.path)
				return
			}
			assert.NoError(t, err, "ordinary decoded path %q must remain supported", tt.path)
		})
	}
}

func TestValidateEscapedAccessPath(t *testing.T) {
	// Malformed escapes and decoded controls normally fail earlier in validateAccessPath.
	// Exercise these guards directly so changes to that ordering cannot silently weaken them.
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "root", path: "/"},
		{name: "unescaped path", path: "/.well-known/file.txt"},
		{name: "encoded space boundary", path: "/file%20name"},
		{name: "encoded last printable ASCII lowercase", path: "/file%7e"},
		{name: "encoded last printable ASCII uppercase", path: "/file%7E"},
		{name: "adjacent escapes", path: "/%41%42%39"},
		{name: "mixed case unicode escapes", path: "/unicode/%C3%a9"},
		{name: "bare escape", path: "/public/%", wantErr: true},
		{name: "short escape", path: "/public/%2", wantErr: true},
		{name: "invalid high nibble", path: "/public/%G0", wantErr: true},
		{name: "invalid low nibble", path: "/public/%0g", wantErr: true},
		{name: "encoded slash lowercase", path: "/public%2fprivate", wantErr: true},
		{name: "encoded slash uppercase", path: "/public%2Fprivate", wantErr: true},
		{name: "encoded backslash lowercase", path: "/public%5cprivate", wantErr: true},
		{name: "encoded backslash uppercase", path: "/public%5Cprivate", wantErr: true},
		{name: "encoded dot lowercase", path: "/file%2etxt", wantErr: true},
		{name: "encoded dot uppercase", path: "/file%2Etxt", wantErr: true},
		{name: "encoded percent", path: "/public/%25", wantErr: true},
		{name: "double encoding", path: "/public/%252e%252e/private", wantErr: true},
		{name: "encoded NUL", path: "/public/%00private", wantErr: true},
		{name: "encoded first non-NUL control", path: "/public/%01private", wantErr: true},
		{name: "encoded tab", path: "/public/%09private", wantErr: true},
		{name: "encoded newline", path: "/public/%0aprivate", wantErr: true},
		{name: "encoded carriage return", path: "/public/%0Dprivate", wantErr: true},
		{name: "encoded last C0 control lowercase", path: "/public/%1fprivate", wantErr: true},
		{name: "encoded last C0 control uppercase", path: "/public/%1Fprivate", wantErr: true},
		{name: "encoded DEL lowercase", path: "/public/%7fprivate", wantErr: true},
		{name: "encoded DEL uppercase", path: "/public/%7Fprivate", wantErr: true},
		{name: "unsafe escape after valid escape", path: "/%41%2fprivate", wantErr: true},
		{name: "malformed escape after valid escape", path: "/%41%", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEscapedAccessPath(tt.path)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrUnsafeRequestPath, "unsafe escaped path %q must be rejected", tt.path)
				return
			}
			assert.NoError(t, err, "ordinary escaped path %q must remain supported", tt.path)
		})
	}
}
