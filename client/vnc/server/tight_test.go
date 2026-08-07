//go:build !js && !ios && !android

package server

import (
	"bytes"
	"image"
	"image/jpeg"
	"testing"
)

func makeUniformImage(w, h int, r, g, b byte) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i+0] = r
		img.Pix[i+1] = g
		img.Pix[i+2] = b
		img.Pix[i+3] = 0xff
	}
	return img
}

func makeTwoColorImage(w, h int) *image.RGBA {
	img := makeUniformImage(w, h, 0x10, 0x20, 0x30)
	fg := [3]byte{0xa0, 0xb0, 0xc0}
	for y := 0; y < h; y++ {
		for x := w / 4; x < w/2; x++ {
			i := y*img.Stride + x*4
			img.Pix[i+0] = fg[0]
			img.Pix[i+1] = fg[1]
			img.Pix[i+2] = fg[2]
		}
	}
	return img
}

func decodeTightLength(buf []byte) (n, consumed int) {
	b0 := buf[0]
	n = int(b0 & 0x7f)
	if b0&0x80 == 0 {
		return n, 1
	}
	b1 := buf[1]
	n |= int(b1&0x7f) << 7
	if b1&0x80 == 0 {
		return n, 2
	}
	b2 := buf[2]
	n |= int(b2) << 14
	return n, 3
}

func TestEncodeTightFill(t *testing.T) {
	pf := defaultClientPixelFormat()
	img := makeUniformImage(64, 64, 0x12, 0x34, 0x56)
	tstate := newTightState()
	buf := encodeTightRect(img, pf, 0, 0, 64, 64, tstate)
	if len(buf) != 12+1+3 {
		t.Fatalf("fill rect should be 16 bytes, got %d", len(buf))
	}
	if buf[12] != tightFillSubenc {
		t.Fatalf("expected fill subenc, got 0x%02x", buf[12])
	}
	if buf[13] != 0x12 || buf[14] != 0x34 || buf[15] != 0x56 {
		t.Fatalf("wrong fill colour: %v", buf[13:16])
	}
}

func TestEncodeTightBasic(t *testing.T) {
	pf := defaultClientPixelFormat()
	img := makeTwoColorImage(64, 64)
	tstate := newTightState()
	buf := encodeTightRect(img, pf, 0, 0, 64, 64, tstate)
	if buf[12]&0xf0 != tightBasicFilter {
		t.Fatalf("expected basic+filter subenc, got 0x%02x", buf[12])
	}
	if buf[13] != tightFilterCopy {
		t.Fatalf("expected copy filter, got 0x%02x", buf[13])
	}
	// Length prefix and zlib stream follow.
	n, _ := decodeTightLength(buf[14:])
	if n == 0 {
		t.Fatalf("zero-length basic stream")
	}
}

func TestEncodeTightJPEG(t *testing.T) {
	pf := defaultClientPixelFormat()
	img := makeBenchImage(128, 128, 7) // random → many colours
	tstate := newTightState()
	buf := encodeTightRect(img, pf, 0, 0, 128, 128, tstate)
	if buf[12] != tightJPEGSubenc {
		t.Fatalf("expected JPEG subenc, got 0x%02x", buf[12])
	}
	n, consumed := decodeTightLength(buf[13:])
	jpegBytes := buf[13+consumed : 13+consumed+n]
	if _, err := jpeg.Decode(bytes.NewReader(jpegBytes)); err != nil {
		t.Fatalf("emitted JPEG bytes do not decode: %v", err)
	}
}

func TestSampledColorCount(t *testing.T) {
	uniform := makeUniformImage(64, 64, 0x10, 0x20, 0x30)
	if c := sampledColorCountInto(map[uint32]struct{}{}, uniform, 0, 0, 64, 64, 32); c != 1 {
		t.Fatalf("uniform should be 1 colour, got %d", c)
	}
	rnd := makeBenchImage(128, 128, 1)
	if c := sampledColorCountInto(map[uint32]struct{}{}, rnd, 0, 0, 128, 128, 16); c <= 16 {
		t.Fatalf("random image should exceed colour cap, got %d", c)
	}
}
