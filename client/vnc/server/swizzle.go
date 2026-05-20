//go:build !js && !ios && !android

package server

import "unsafe"

// swizzleBGRAtoRGBA swaps B and R channels in a BGRA pixel buffer and copies
// into dst in-place (dst and src may alias). Operates on uint32 words: one
// read-modify-write per pixel, which is meaningfully faster than the naive
// three-byte-store per pixel for large buffers like framebuffers.
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
	dp := unsafe.Slice((*uint32)(unsafe.Pointer(&dst[0])), n)
	sp := unsafe.Slice((*uint32)(unsafe.Pointer(&src[0])), n)
	for i := range n {
		p := sp[i]
		// p in memory: B, G, R, A -> as uint32 little-endian: 0xAARRGGBB
		// Want memory: R, G, B, 0xFF -> uint32 little-endian: 0xFFBBGGRR
		dp[i] = 0xFF000000 | (p & 0x0000FF00) | ((p & 0x00FF0000) >> 16) | ((p & 0x000000FF) << 16)
	}
}
