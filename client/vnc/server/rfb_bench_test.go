package server

import (
	"image"
	"math/rand"
	"testing"
)

// Representative frame sizes.
var benchRects = []struct {
	name string
	w, h int
}{
	{"1080p_full", 1920, 1080},
	{"720p_full", 1280, 720},
	{"256x256_tile", 256, 256},
	{"64x64_tile", 64, 64},
}

func makeBenchImage(w, h int, seed int64) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	r := rand.New(rand.NewSource(seed))
	_, _ = r.Read(img.Pix)
	// Force alpha byte so the fast path and slow path produce identical output.
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 0xff
	}
	return img
}

func makeBenchImagePartial(w, h, changedRows int) (*image.RGBA, *image.RGBA) {
	prev := makeBenchImage(w, h, 1)
	cur := image.NewRGBA(prev.Rect)
	copy(cur.Pix, prev.Pix)
	if changedRows > h {
		changedRows = h
	}
	// Dirty the first `changedRows` rows.
	r := rand.New(rand.NewSource(2))
	_, _ = r.Read(cur.Pix[:changedRows*cur.Stride])
	for i := 3; i < len(cur.Pix); i += 4 {
		cur.Pix[i] = 0xff
	}
	return prev, cur
}

func BenchmarkEncodeRawRect(b *testing.B) {
	pf := defaultClientPixelFormat()
	for _, r := range benchRects {
		img := makeBenchImage(r.w, r.h, 1)
		b.Run(r.name, func(b *testing.B) {
			b.SetBytes(int64(r.w * r.h * 4))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = encodeRawRect(img, pf, 0, 0, r.w, r.h)
			}
		})
	}
}

func BenchmarkEncodeZlibRect(b *testing.B) {
	pf := defaultClientPixelFormat()
	for _, r := range benchRects {
		img := makeBenchImage(r.w, r.h, 1)
		z := newZlibState()
		b.Run(r.name, func(b *testing.B) {
			b.SetBytes(int64(r.w * r.h * 4))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = encodeZlibRect(img, pf, 0, 0, r.w, r.h, z)
			}
		})
	}
}

// BenchmarkWritePixels isolates the per-pixel pack loop from the allocation
// and FramebufferUpdate-header overhead.
func BenchmarkWritePixels(b *testing.B) {
	pf := defaultClientPixelFormat()
	for _, r := range benchRects {
		img := makeBenchImage(r.w, r.h, 1)
		dst := make([]byte, r.w*r.h*4)
		b.Run(r.name, func(b *testing.B) {
			b.SetBytes(int64(r.w * r.h * 4))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				writePixels(dst, img, pf, rect{0, 0, r.w, r.h}, 4)
			}
		})
	}
}

// BenchmarkWritePixelsScaled forces the general (non-fast) path by using a
// pixel format with non-255 channel maxes.
func BenchmarkWritePixelsScaled(b *testing.B) {
	pf := defaultClientPixelFormat()
	pf.rMax, pf.gMax, pf.bMax = 31, 63, 31 // 16bpp-ish; exercises the divide path
	pf.bpp = 16
	for _, r := range benchRects {
		img := makeBenchImage(r.w, r.h, 1)
		dst := make([]byte, r.w*r.h*2)
		b.Run(r.name, func(b *testing.B) {
			b.SetBytes(int64(r.w * r.h * 4))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				writePixels(dst, img, pf, rect{0, 0, r.w, r.h}, 2)
			}
		})
	}
}

func BenchmarkSwizzleBGRAtoRGBA(b *testing.B) {
	for _, r := range benchRects {
		size := r.w * r.h * 4
		src := make([]byte, size)
		dst := make([]byte, size)
		rng := rand.New(rand.NewSource(1))
		_, _ = rng.Read(src)
		b.Run(r.name, func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				swizzleBGRAtoRGBA(dst, src)
			}
		})
	}
}

// BenchmarkSwizzleBGRAtoRGBANaive is the naive byte-by-byte implementation
// that the Linux SHM capturer used before the uint32 rewrite, kept here so
// we can compare the cost directly.
func BenchmarkSwizzleBGRAtoRGBANaive(b *testing.B) {
	for _, r := range benchRects {
		size := r.w * r.h * 4
		src := make([]byte, size)
		dst := make([]byte, size)
		rng := rand.New(rand.NewSource(1))
		_, _ = rng.Read(src)
		b.Run(r.name, func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for j := 0; j < size; j += 4 {
					dst[j+0] = src[j+2]
					dst[j+1] = src[j+1]
					dst[j+2] = src[j+0]
					dst[j+3] = 0xff
				}
			}
		})
	}
}

// BenchmarkEncodeUniformTile_Zlib measures the cost of sending a uniform
// 64×64 dirty tile via zlib (the old path before the Hextile fast path).
func BenchmarkEncodeUniformTile_Zlib(b *testing.B) {
	pf := defaultClientPixelFormat()
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i+0] = 0x33
		img.Pix[i+1] = 0x66
		img.Pix[i+2] = 0x99
		img.Pix[i+3] = 0xff
	}
	z := newZlibState()
	b.ReportAllocs()
	var bytesOut int
	for i := 0; i < b.N; i++ {
		out := encodeZlibRect(img, pf, 0, 0, 64, 64, z)
		bytesOut = len(out)
	}
	b.ReportMetric(float64(bytesOut), "wire_bytes")
}

// BenchmarkEncodeUniformTile_Hextile measures the new fast path: uniform
// 64×64 tile emitted as Hextile SolidFill.
func BenchmarkEncodeUniformTile_Hextile(b *testing.B) {
	pf := defaultClientPixelFormat()
	b.ReportAllocs()
	var bytesOut int
	for i := 0; i < b.N; i++ {
		out := encodeHextileSolidRect(0x33, 0x66, 0x99, pf, rect{0, 0, 64, 64})
		bytesOut = len(out)
	}
	b.ReportMetric(float64(bytesOut), "wire_bytes")
}

func BenchmarkTileIsUniform(b *testing.B) {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i+3] = 0xff
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = tileIsUniform(img, 0, 0, 64, 64)
	}
}

// BenchmarkEncodeManyTilesVsFullFrame exercises the bandwidth + CPU
// trade-off that motivates the full-frame promotion path: encoding a burst
// of N dirty 64×64 tiles as separate zlib rects vs emitting one big zlib
// rect for the whole frame.
func BenchmarkEncodeManyTilesVsFullFrame(b *testing.B) {
	pf := defaultClientPixelFormat()
	const w, h = 1920, 1080
	img := makeBenchImage(w, h, 1)

	// Build the list of every tile in the frame (worst case: entire screen dirty).
	var tiles [][4]int
	for ty := 0; ty < h; ty += tileSize {
		th := tileSize
		if ty+th > h {
			th = h - ty
		}
		for tx := 0; tx < w; tx += tileSize {
			tw := tileSize
			if tx+tw > w {
				tw = w - tx
			}
			tiles = append(tiles, [4]int{tx, ty, tw, th})
		}
	}
	nTiles := len(tiles)

	b.Run("per_tile_zlib", func(b *testing.B) {
		z := newZlibState()
		b.SetBytes(int64(w * h * 4))
		b.ReportAllocs()
		var totalOut int
		for i := 0; i < b.N; i++ {
			totalOut = 0
			for _, r := range tiles {
				out := encodeZlibRect(img, pf, r[0], r[1], r[2], r[3], z)
				totalOut += len(out)
			}
		}
		b.ReportMetric(float64(totalOut), "wire_bytes")
		b.ReportMetric(float64(nTiles), "tiles")
	})

	b.Run("full_frame_zlib", func(b *testing.B) {
		z := newZlibState()
		b.SetBytes(int64(w * h * 4))
		b.ReportAllocs()
		var totalOut int
		for i := 0; i < b.N; i++ {
			out := encodeZlibRect(img, pf, 0, 0, w, h, z)
			totalOut = len(out)
		}
		b.ReportMetric(float64(totalOut), "wire_bytes")
	})
}

// BenchmarkShouldPromoteToFullFrame verifies the threshold check itself is
// cheap. It runs on every frame, so regressions here hit all workloads.
func BenchmarkShouldPromoteToFullFrame(b *testing.B) {
	const w, h = 1920, 1080
	s := &session{serverW: w, serverH: h}
	// Build a worst-case rect list (every tile dirty, 510 entries).
	var rects [][4]int
	for ty := 0; ty < h; ty += tileSize {
		th := tileSize
		if ty+th > h {
			th = h - ty
		}
		for tx := 0; tx < w; tx += tileSize {
			tw := tileSize
			if tx+tw > w {
				tw = w - tx
			}
			rects = append(rects, [4]int{tx, ty, tw, th})
		}
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = s.shouldPromoteToFullFrame(rects)
	}
}

// BenchmarkEncodeCoalescedVsPerTile compares per-tile encoding vs the
// coalesced rect list emitted by diffRects, on a horizontal-band dirty
// pattern (e.g. a scrolling status bar) where coalescing pays off.
func BenchmarkEncodeCoalescedVsPerTile(b *testing.B) {
	pf := defaultClientPixelFormat()
	const w, h = 1920, 1080
	img := makeBenchImage(w, h, 1)

	// Dirty band: rows 200..264 (one tile-row), full width.
	var perTile [][4]int
	for tx := 0; tx < w; tx += tileSize {
		tw := tileSize
		if tx+tw > w {
			tw = w - tx
		}
		perTile = append(perTile, [4]int{tx, 200, tw, tileSize})
	}
	coalesced := coalesceRects(append([][4]int(nil), perTile...))

	b.Run("per_tile", func(b *testing.B) {
		z := newZlibState()
		b.ReportAllocs()
		var bytesOut int
		for i := 0; i < b.N; i++ {
			bytesOut = 0
			for _, r := range perTile {
				out := encodeZlibRect(img, pf, r[0], r[1], r[2], r[3], z)
				bytesOut += len(out)
			}
		}
		b.ReportMetric(float64(bytesOut), "wire_bytes")
		b.ReportMetric(float64(len(perTile)), "rects")
	})

	b.Run("coalesced", func(b *testing.B) {
		z := newZlibState()
		b.ReportAllocs()
		var bytesOut int
		for i := 0; i < b.N; i++ {
			bytesOut = 0
			for _, r := range coalesced {
				out := encodeZlibRect(img, pf, r[0], r[1], r[2], r[3], z)
				bytesOut += len(out)
			}
		}
		b.ReportMetric(float64(bytesOut), "wire_bytes")
		b.ReportMetric(float64(len(coalesced)), "rects")
	})
}

func BenchmarkCoalesceRects(b *testing.B) {
	const w, h = 1920, 1080
	// Worst case: every tile dirty.
	var allTiles [][4]int
	for ty := 0; ty < h; ty += tileSize {
		th := tileSize
		if ty+th > h {
			th = h - ty
		}
		for tx := 0; tx < w; tx += tileSize {
			tw := tileSize
			if tx+tw > w {
				tw = w - tx
			}
			allTiles = append(allTiles, [4]int{tx, ty, tw, th})
		}
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		in := make([][4]int, len(allTiles))
		copy(in, allTiles)
		_ = coalesceRects(in)
	}
}

// BenchmarkEncodeTightVsZlib_Photo compares Tight (which routes random/
// photographic content to JPEG) against the persistent Zlib stream. JPEG
// at quality 70 should be 5-15× smaller on this kind of content.
func BenchmarkEncodeTightVsZlib_Photo(b *testing.B) {
	pf := defaultClientPixelFormat()
	for _, r := range []struct {
		name string
		w, h int
	}{
		{"256x256", 256, 256},
		{"512x512", 512, 512},
		{"1080p", 1920, 1080},
	} {
		img := makeBenchImage(r.w, r.h, 1)
		b.Run(r.name+"/zlib", func(b *testing.B) {
			z := newZlibState()
			b.SetBytes(int64(r.w * r.h * 4))
			b.ReportAllocs()
			var bytesOut int
			for i := 0; i < b.N; i++ {
				out := encodeZlibRect(img, pf, 0, 0, r.w, r.h, z)
				bytesOut = len(out)
			}
			b.ReportMetric(float64(bytesOut), "wire_bytes")
		})
		b.Run(r.name+"/tight", func(b *testing.B) {
			t := newTightState()
			b.SetBytes(int64(r.w * r.h * 4))
			b.ReportAllocs()
			var bytesOut int
			for i := 0; i < b.N; i++ {
				out := encodeTightRect(img, pf, 0, 0, r.w, r.h, t)
				bytesOut = len(out)
			}
			b.ReportMetric(float64(bytesOut), "wire_bytes")
		})
	}
}

func BenchmarkDiffRects(b *testing.B) {
	for _, r := range benchRects {
		prev, cur := makeBenchImagePartial(r.w, r.h, 100)
		b.Run(r.name, func(b *testing.B) {
			b.SetBytes(int64(r.w * r.h * 4))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = diffRects(prev, cur, r.w, r.h, tileSize)
			}
		})
	}
}
