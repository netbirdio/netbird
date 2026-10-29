package instancecolor

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
)

const (
	// dotFraction is the diameter of the coloured dot and ringFraction the
	// width of the ring around it, both relative to the icon width. Windows
	// scales the 256 px icons down to 16 px, so the dot has to be large and the
	// ring is what keeps it visible on any taskbar.
	dotFraction  = 0.40
	ringFraction = 0.06
)

var (
	// RingOnLight is drawn around the dot on icons meant for a light taskbar.
	RingOnLight = color.NRGBA{R: 0x1f, G: 0x1f, B: 0x1f, A: 0xff}
	// RingOnDark is drawn around the dot on icons meant for a dark taskbar.
	RingOnDark = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
)

// DotBounds returns the square the dot and its ring occupy in an icon of the
// given bounds: the top-left corner, the one no tray state uses. Pixels outside
// it are never changed.
func DotBounds(b image.Rectangle) image.Rectangle {
	size := int(math.Ceil(2 * outerRadius(b.Dx())))
	return image.Rect(b.Min.X, b.Min.Y, b.Min.X+size, b.Min.Y+size).Intersect(b)
}

// Overlay returns the PNG icon with a dot of colour fill and a ring of colour
// ring drawn in its top-left corner, at the icon's native size.
func Overlay(icon []byte, fill, ring color.NRGBA) ([]byte, error) {
	return overlayAt(icon, fill, ring, func(b image.Rectangle) float64 {
		return outerRadius(b.Dx())
	})
}

// NotificationLogo returns the PNG icon with the dot moved towards the centre
// along the diagonal, just enough that the circle Windows crops notification
// logos to keeps the whole dot and ring, including its anti-aliased edge.
func NotificationLogo(icon []byte, fill, ring color.NRGBA) ([]byte, error) {
	return overlayAt(icon, fill, ring, func(b image.Rectangle) float64 {
		const edge = 1
		half := float64(b.Dx()) / 2
		return half - (half-outerRadius(b.Dx())-edge)/math.Sqrt2
	})
}

// overlayAt draws the dot centred at (offset, offset) from the icon's top-left
// corner.
func overlayAt(icon []byte, fill, ring color.NRGBA, offset func(image.Rectangle) float64) ([]byte, error) {
	src, err := png.Decode(bytes.NewReader(icon))
	if err != nil {
		return nil, fmt.Errorf("decode icon: %w", err)
	}
	b := src.Bounds()
	dst := image.NewNRGBA(b)
	draw.Draw(dst, b, src, b.Min, draw.Src)

	outer := outerRadius(b.Dx())
	inner := float64(b.Dx()) * dotFraction / 2
	cx, cy := float64(b.Min.X)+offset(b), float64(b.Min.Y)+offset(b)

	area := image.Rect(
		int(math.Floor(cx-outer)), int(math.Floor(cy-outer)),
		int(math.Ceil(cx+outer)), int(math.Ceil(cy+outer)),
	).Intersect(b)
	for y := area.Min.Y; y < area.Max.Y; y++ {
		for x := area.Min.X; x < area.Max.X; x++ {
			d := math.Hypot(float64(x)+0.5-cx, float64(y)+0.5-cy)
			coverage := clamp01(outer - d + 0.5)
			if coverage == 0 {
				continue
			}
			paint := mix(ring, fill, clamp01(inner-d+0.5))
			dst.SetNRGBA(x, y, over(paint, coverage, dst.NRGBAAt(x, y)))
		}
	}

	var out bytes.Buffer
	if err := png.Encode(&out, dst); err != nil {
		return nil, fmt.Errorf("encode icon: %w", err)
	}
	return out.Bytes(), nil
}

func outerRadius(width int) float64 {
	return float64(width) * (dotFraction/2 + ringFraction)
}

func clamp01(v float64) float64 {
	return math.Max(0, math.Min(1, v))
}

// mix blends two opaque colours, t = 1 giving b.
func mix(a, b color.NRGBA, t float64) color.NRGBA {
	l := func(x, y uint8) uint8 { return uint8(math.Round(float64(x)*(1-t) + float64(y)*t)) }
	return color.NRGBA{R: l(a.R, b.R), G: l(a.G, b.G), B: l(a.B, b.B), A: 0xff}
}

// over composites an opaque colour with the given coverage over dst.
func over(src color.NRGBA, coverage float64, dst color.NRGBA) color.NRGBA {
	da := float64(dst.A) / 255
	oa := coverage + da*(1-coverage)
	if oa == 0 {
		return color.NRGBA{}
	}
	c := func(s, d uint8) uint8 {
		return uint8(math.Round((float64(s)*coverage + float64(d)*da*(1-coverage)) / oa))
	}
	return color.NRGBA{R: c(src.R, dst.R), G: c(src.G, dst.G), B: c(src.B, dst.B), A: uint8(math.Round(oa * 255))}
}
