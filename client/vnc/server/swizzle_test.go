//go:build !js && !ios && !android

package server

import (
	"image"
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

// A destination with padded rows must get each row at its own offset, with the
// padding left alone, rather than having the pixels run on into it.
func TestSwizzleBGRAIntoImage_PaddedStride(t *testing.T) {
	const w, h = 2, 2
	src := []byte{
		0x01, 0x02, 0x03, 0x00, 0x04, 0x05, 0x06, 0x00,
		0x07, 0x08, 0x09, 0x00, 0x0a, 0x0b, 0x0c, 0x00,
	}
	// Four bytes of padding per row, filled with a marker that must survive.
	dst := &image.RGBA{Pix: make([]byte, 2*(w*4+4)), Stride: w*4 + 4, Rect: image.Rect(0, 0, w, h)}
	for i := range dst.Pix {
		dst.Pix[i] = 0xee
	}

	swizzleBGRAIntoImage(dst, src, w, h)

	assert.Equal(t, []byte{0x03, 0x02, 0x01, 0xff, 0x06, 0x05, 0x04, 0xff}, dst.Pix[0:8], "row 0 pixels")
	assert.Equal(t, []byte{0xee, 0xee, 0xee, 0xee}, dst.Pix[8:12], "row 0 padding untouched")
	assert.Equal(t, []byte{0x09, 0x08, 0x07, 0xff, 0x0c, 0x0b, 0x0a, 0xff}, dst.Pix[12:20], "row 1 pixels")
}
