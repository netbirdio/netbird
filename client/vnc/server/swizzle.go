//go:build !js && !ios && !android

package server

import (
	"encoding/binary"
	"image"
	"unsafe"
)

// nativeIsLittleEndian reports the byte order of the target. The word-at-a-time
// swizzle below only holds on a little-endian layout, and the client ships
// big-endian linux/mips and linux/mips64 builds.
var nativeIsLittleEndian = binary.NativeEndian.Uint16([]byte{1, 0}) == 1

// swizzleBGRAtoRGBA swaps B and R channels in a BGRA pixel buffer and copies
// into dst in-place (dst and src may alias).
//
// The alpha byte is forced to 0xff so callers that capture from X11 GetImage
// (where the X server leaves the pad byte as zero) still get an opaque image.
func swizzleBGRAtoRGBA(dst, src []byte) {
	n := len(dst) / 4
	if len(src)/4 < n {
		n = len(src) / 4
	}
	if n == 0 {
		return
	}
	if !nativeIsLittleEndian {
		swizzleBGRAtoRGBABytes(dst[:n*4], src[:n*4])
		return
	}

	// One read-modify-write per pixel, meaningfully faster than three byte
	// stores over a whole framebuffer. The masks below describe a little-endian
	// word, so this path is guarded above rather than used unconditionally.
	dp := unsafe.Slice((*uint32)(unsafe.Pointer(&dst[0])), n)
	sp := unsafe.Slice((*uint32)(unsafe.Pointer(&src[0])), n)
	for i := range n {
		p := sp[i]
		// p in memory: B, G, R, A -> as uint32 little-endian: 0xAARRGGBB
		// Want memory: R, G, B, 0xFF -> uint32 little-endian: 0xFFBBGGRR
		dp[i] = 0xFF000000 | (p & 0x0000FF00) | ((p & 0x00FF0000) >> 16) | ((p & 0x000000FF) << 16)
	}
}

// swizzleBGRAtoRGBABytes is the byte-order-independent form, used on big-endian
// targets. It converts whole pixels for as long as both sides have one left.
func swizzleBGRAtoRGBABytes(dst, src []byte) {
	for i := 0; i+4 <= len(src) && i+4 <= len(dst); i += 4 {
		s := src[i : i+4 : i+4]
		d := dst[i : i+4 : i+4]
		d[0], d[1], d[2], d[3] = s[2], s[1], s[0], 0xFF
	}
}

// swizzleBGRAIntoImage converts a tightly packed w x h BGRA source into dst.
// dst may be any image.RGBA of that size, including one whose rows are padded
// (a SubImage, or a buffer allocated with a wider stride): swizzleBGRAtoRGBA on
// dst.Pix as a whole would then write pixel data into the padding and shift
// every row after the first. A packed dst still takes the single-pass path.
func swizzleBGRAIntoImage(dst *image.RGBA, src []byte, w, h int) {
	rowBytes := w * 4
	if dst.Stride == rowBytes {
		swizzleBGRAtoRGBA(dst.Pix[:rowBytes*h], src[:rowBytes*h])
		return
	}
	for y := 0; y < h; y++ {
		d := dst.Pix[y*dst.Stride : y*dst.Stride+rowBytes]
		swizzleBGRAtoRGBA(d, src[y*rowBytes:(y+1)*rowBytes])
	}
}
