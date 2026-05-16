package server

import (
	"image"
	"testing"
)

// roundTrip decodes an encoded Hextile rect back into pixels and checks it
// matches the source. Implements just enough of the noVNC Hextile decoder
// to validate our encoder.
func decodeHextile(t *testing.T, buf []byte, pf clientPixelFormat) *image.RGBA {
	t.Helper()
	if len(buf) < 12 {
		t.Fatalf("buf too short: %d", len(buf))
	}
	x := int(uint16(buf[0])<<8 | uint16(buf[1]))
	y := int(uint16(buf[2])<<8 | uint16(buf[3]))
	w := int(uint16(buf[4])<<8 | uint16(buf[5]))
	h := int(uint16(buf[6])<<8 | uint16(buf[7]))
	enc := uint32(buf[8])<<24 | uint32(buf[9])<<16 | uint32(buf[10])<<8 | uint32(buf[11])
	if enc != encHextile {
		t.Fatalf("not hextile: %d", enc)
	}
	body := buf[12:]
	bytesPerPixel := max(int(pf.bpp)/8, 1)
	out := image.NewRGBA(image.Rect(x, y, x+w, y+h))

	var bg, fg [3]byte
	pos := 0
	readPixel := func() [3]byte {
		var v uint32
		if pf.bigEndian != 0 {
			for i := 0; i < bytesPerPixel; i++ {
				v |= uint32(body[pos+i]) << (8 * (bytesPerPixel - 1 - i))
			}
		} else {
			for i := 0; i < bytesPerPixel; i++ {
				v |= uint32(body[pos+i]) << (8 * i)
			}
		}
		pos += bytesPerPixel
		r := byte((v >> pf.rShift) & uint32(pf.rMax))
		g := byte((v >> pf.gShift) & uint32(pf.gMax))
		b := byte((v >> pf.bShift) & uint32(pf.bMax))
		return [3]byte{r, g, b}
	}
	for sy := 0; sy < h; sy += hextileSubSize {
		sh := min(hextileSubSize, h-sy)
		for sx := 0; sx < w; sx += hextileSubSize {
			sw := min(hextileSubSize, w-sx)
			flags := body[pos]
			pos++
			if flags&hextileRaw != 0 {
				for ry := 0; ry < sh; ry++ {
					for rx := 0; rx < sw; rx++ {
						px := readPixel()
						i := (sy+ry)*out.Stride + (sx+rx)*4
						out.Pix[i+0] = px[0]
						out.Pix[i+1] = px[1]
						out.Pix[i+2] = px[2]
						out.Pix[i+3] = 0xff
					}
				}
				continue
			}
			if flags&hextileBackgroundSpecified != 0 {
				bg = readPixel()
			}
			if flags&hextileForegroundSpecified != 0 {
				fg = readPixel()
			}
			// Fill sub-tile with bg.
			for ry := 0; ry < sh; ry++ {
				for rx := 0; rx < sw; rx++ {
					i := (sy+ry)*out.Stride + (sx+rx)*4
					out.Pix[i+0] = bg[0]
					out.Pix[i+1] = bg[1]
					out.Pix[i+2] = bg[2]
					out.Pix[i+3] = 0xff
				}
			}
			if flags&hextileAnySubrects == 0 {
				continue
			}
			n := int(body[pos])
			pos++
			for k := 0; k < n; k++ {
				color := fg
				if flags&hextileSubrectsColoured != 0 {
					color = readPixel()
				}
				xy := body[pos]
				wh := body[pos+1]
				pos += 2
				rxr := int(xy >> 4)
				ryr := int(xy & 0x0f)
				rwr := int(wh>>4) + 1
				rhr := int(wh&0x0f) + 1
				for ry := 0; ry < rhr; ry++ {
					for rx := 0; rx < rwr; rx++ {
						i := (sy+ryr+ry)*out.Stride + (sx+rxr+rx)*4
						out.Pix[i+0] = color[0]
						out.Pix[i+1] = color[1]
						out.Pix[i+2] = color[2]
						out.Pix[i+3] = 0xff
					}
				}
			}
		}
	}
	return out
}

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
	// Draw a vertical bar of fg in the middle.
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

func compareImages(t *testing.T, want, got *image.RGBA) {
	t.Helper()
	if want.Rect != got.Rect {
		t.Fatalf("rect mismatch: %v vs %v", want.Rect, got.Rect)
	}
	w, h := want.Rect.Dx(), want.Rect.Dy()
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := y*want.Stride + x*4
			j := y*got.Stride + x*4
			if want.Pix[i] != got.Pix[j] || want.Pix[i+1] != got.Pix[j+1] || want.Pix[i+2] != got.Pix[j+2] {
				t.Fatalf("pixel mismatch at (%d,%d): want %v got %v",
					x, y, want.Pix[i:i+3], got.Pix[j:j+3])
			}
		}
	}
}

func TestEncodeHextileRect_Uniform(t *testing.T) {
	pf := defaultClientPixelFormat()
	img := makeUniformImage(64, 64, 0x33, 0x66, 0x99)
	buf := encodeHextileRect(img, pf, 0, 0, 64, 64)
	got := decodeHextile(t, buf, pf)
	compareImages(t, img, got)
}

func TestEncodeHextileRect_TwoColor(t *testing.T) {
	pf := defaultClientPixelFormat()
	img := makeTwoColorImage(64, 64)
	buf := encodeHextileRect(img, pf, 0, 0, 64, 64)
	got := decodeHextile(t, buf, pf)
	compareImages(t, img, got)
}

func TestEncodeHextileRect_Multicolor(t *testing.T) {
	pf := defaultClientPixelFormat()
	img := makeBenchImage(64, 64, 42)
	buf := encodeHextileRect(img, pf, 0, 0, 64, 64)
	got := decodeHextile(t, buf, pf)
	compareImages(t, img, got)
}

func TestEncodeHextileRect_NonAligned(t *testing.T) {
	pf := defaultClientPixelFormat()
	img := makeTwoColorImage(50, 33) // not a multiple of 16
	buf := encodeHextileRect(img, pf, 0, 0, 50, 33)
	got := decodeHextile(t, buf, pf)
	compareImages(t, img, got)
}
