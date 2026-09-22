//go:build !js && !ios && !android

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Both swizzle paths must agree: the word-at-a-time one runs on little-endian
// targets, the byte one on the big-endian mips builds the client also ships.
func TestSwizzleBGRAtoRGBA_PathsAgree(t *testing.T) {
	src := []byte{
		0x11, 0x22, 0x33, 0x00, // B G R pad
		0xAA, 0xBB, 0xCC, 0xFF,
	}
	want := []byte{
		0x33, 0x22, 0x11, 0xFF, // R G B opaque
		0xCC, 0xBB, 0xAA, 0xFF,
	}

	fast := make([]byte, len(src))
	swizzleBGRAtoRGBA(fast, src)
	assert.Equal(t, want, fast, "swizzle must produce opaque RGBA")

	portable := make([]byte, len(src))
	swizzleBGRAtoRGBABytes(portable, src)
	assert.Equal(t, want, portable, "the byte path must match the word path")
}

// dst and src may alias; in-place must give the same answer.
func TestSwizzleBGRAtoRGBA_InPlace(t *testing.T) {
	buf := []byte{0x11, 0x22, 0x33, 0x00}
	swizzleBGRAtoRGBA(buf, buf)
	assert.Equal(t, []byte{0x33, 0x22, 0x11, 0xFF}, buf)
}
