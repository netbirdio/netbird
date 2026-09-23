//go:build freebsd

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
