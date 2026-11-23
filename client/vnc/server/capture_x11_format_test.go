//go:build (linux && !android) || freebsd

package server

import (
	"testing"

	"github.com/jezek/xgb/xproto"
	"github.com/stretchr/testify/assert"
)

// The capturer decodes every frame as 32-bit BGRA. A screen that is not laid
// out that way has to be refused at startup: accepted, it produces a
// successful-looking session whose every frame has swapped or garbage colours.
func TestCheckPixmapFormat(t *testing.T) {
	const rootVisual xproto.Visualid = 0x21

	build := func(depth, bpp byte, order byte, r, g, b uint32) (*xproto.SetupInfo, *xproto.ScreenInfo) {
		setup := &xproto.SetupInfo{
			ImageByteOrder: order,
			PixmapFormats:  []xproto.Format{{Depth: depth, BitsPerPixel: bpp}},
		}
		screen := &xproto.ScreenInfo{
			RootDepth:  depth,
			RootVisual: rootVisual,
			AllowedDepths: []xproto.DepthInfo{{
				Depth: depth,
				Visuals: []xproto.VisualInfo{{
					VisualId: rootVisual, RedMask: r, GreenMask: g, BlueMask: b,
				}},
			}},
		}
		return setup, screen
	}

	tests := []struct {
		name    string
		depth   byte
		bpp     byte
		order   byte
		r, g, b uint32
		wantErr bool
	}{
		{"depth 24 in 32 bits, LSB first, RGB masks", 24, 32, xproto.ImageOrderLSBFirst, 0xff0000, 0xff00, 0xff, false},
		{"depth 32", 32, 32, xproto.ImageOrderLSBFirst, 0xff0000, 0xff00, 0xff, false},
		{"16-bit screen", 16, 16, xproto.ImageOrderLSBFirst, 0xf800, 0x7e0, 0x1f, true},
		{"packed 24 bits per pixel", 24, 24, xproto.ImageOrderLSBFirst, 0xff0000, 0xff00, 0xff, true},
		{"MSB-first byte order", 24, 32, xproto.ImageOrderMSBFirst, 0xff0000, 0xff00, 0xff, true},
		{"BGR visual", 24, 32, xproto.ImageOrderLSBFirst, 0xff, 0xff00, 0xff0000, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setup, screen := build(tc.depth, tc.bpp, tc.order, tc.r, tc.g, tc.b)
			err := checkPixmapFormat(setup, screen)
			if tc.wantErr {
				assert.Error(t, err, "a layout the BGRA decoder cannot read must be refused")
			} else {
				assert.NoError(t, err, "the standard 32-bit BGRA layout must be accepted")
			}
		})
	}
}

// A root visual that the screen does not list cannot be checked, so it is
// refused rather than assumed.
func TestCheckPixmapFormat_UnknownRootVisual(t *testing.T) {
	setup := &xproto.SetupInfo{
		ImageByteOrder: xproto.ImageOrderLSBFirst,
		PixmapFormats:  []xproto.Format{{Depth: 24, BitsPerPixel: 32}},
	}
	screen := &xproto.ScreenInfo{RootDepth: 24, RootVisual: 0x99}
	assert.Error(t, checkPixmapFormat(setup, screen))
}
