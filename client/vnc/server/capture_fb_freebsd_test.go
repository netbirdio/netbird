//go:build freebsd

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fb_depth is colour depth, not storage: a KMS console is depth 24 stored as
// 32-bit XRGB, and decoding it as packed 24-bit reads every row at the wrong
// width. The row pitch decides which it is.
func TestFreebsdStorageBits(t *testing.T) {
	tests := []struct {
		name   string
		depth  int32
		width  int32
		stride int
		want   int
	}{
		{"depth 24 in 32-bit pixels", 24, 1024, 4096, 32},
		{"depth 24 in 32-bit pixels with padding", 24, 1000, 4096, 32},
		{"packed depth 24", 24, 1024, 3072, 24},
		{"depth 32", 32, 1024, 4096, 32},
		{"depth 16", 16, 1024, 2048, 16},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := freebsdStorageBits(fbType{FbDepth: tc.depth, FbWidth: tc.width}, tc.stride)
			assert.Equal(t, tc.want, got, "storage bits per pixel")
		})
	}
}

// The row pitch is derived from the mapping, not computed from width and
// depth: a KMS framebuffer pads its rows, and reading at the unpadded width
// shears the image. A mapping too small for the reported geometry would have
// rows read off its end, so it is refused rather than guessed at.
func TestFreebsdFBStride(t *testing.T) {
	tests := []struct {
		name    string
		fbt     fbType
		want    int
		wantErr bool
	}{
		{"unpadded 32-bit", fbType{FbWidth: 1024, FbHeight: 768, FbDepth: 32, FbSize: 1024 * 768 * 4}, 4096, false},
		{"padded rows", fbType{FbWidth: 1000, FbHeight: 768, FbDepth: 32, FbSize: 4096 * 768}, 4096, false},
		{"packed 24-bit", fbType{FbWidth: 1024, FbHeight: 768, FbDepth: 24, FbSize: 1024 * 768 * 3}, 3072, false},
		{"16-bit", fbType{FbWidth: 800, FbHeight: 600, FbDepth: 16, FbSize: 800 * 600 * 2}, 1600, false},
		{"size cannot hold the geometry", fbType{FbWidth: 1024, FbHeight: 768, FbDepth: 32, FbSize: 1024 * 768 * 2}, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := freebsdFBStride(tc.fbt)
			if tc.wantErr {
				require.Error(t, err, "a mapping smaller than the geometry must be refused")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got, "row pitch in bytes")
		})
	}
}
