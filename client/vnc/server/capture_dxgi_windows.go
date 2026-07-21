//go:build windows

package server

import (
	"errors"
	"fmt"
	"image"

	"github.com/kirides/go-d3d/d3d11"
	"github.com/kirides/go-d3d/outputduplication"
)

// dxgiCapturer captures the desktop using DXGI Desktop Duplication.
// Provides GPU-accelerated capture with native dirty rect tracking.
// Only works from the interactive user session, not Session 0.
//
// Uses a double-buffer: DXGI writes into img, then we copy to the current
// output buffer and hand it out. Alternating between two output buffers
// avoids allocating a new image.RGBA per frame (~8MB at 1080p, 30fps).
type dxgiCapturer struct {
	dup    *outputduplication.OutputDuplicator
	device *d3d11.ID3D11Device
	ctx    *d3d11.ID3D11DeviceContext
	img    *image.RGBA
	out    [2]*image.RGBA
	outIdx int
	width  int
	height int
}

func newDXGICapturer() (*dxgiCapturer, error) {
	device, deviceCtx, err := d3d11.NewD3D11Device()
	if err != nil {
		return nil, fmt.Errorf("create D3D11 device: %w", err)
	}

	dup, err := outputduplication.NewIDXGIOutputDuplication(device, deviceCtx, 0)
	if err != nil {
		device.Release()
		deviceCtx.Release()
		return nil, fmt.Errorf("create output duplication: %w", err)
	}

	w, h := screenSize()
	if w == 0 || h == 0 {
		dup.Release()
		device.Release()
		deviceCtx.Release()
		return nil, fmt.Errorf("screen dimensions are zero")
	}

	rect := image.Rect(0, 0, w, h)
	c := &dxgiCapturer{
		dup:    dup,
		device: device,
		ctx:    deviceCtx,
		img:    image.NewRGBA(rect),
		out:    [2]*image.RGBA{image.NewRGBA(rect), image.NewRGBA(rect)},
		width:  w,
		height: h,
	}

	// Grab the initial frame with a longer timeout to ensure we have
	// a valid image before returning.
	_ = dup.GetImage(c.img, 2000)

	return c, nil
}

func (c *dxgiCapturer) capture() (*image.RGBA, error) {
	err := c.dup.GetImage(c.img, 100)
	if err != nil && !errors.Is(err, outputduplication.ErrNoImageYet) {
		return nil, err
	}

	// Copy into the next output buffer. The DesktopCapturer hands out the
	// returned pointer to VNC sessions that read pixels concurrently, so we
	// alternate between two pre-allocated buffers instead of allocating per frame.
	out := c.out[c.outIdx]
	c.outIdx ^= 1
	copy(out.Pix, c.img.Pix)
	return out, nil
}

func (c *dxgiCapturer) close() {
	if c.dup != nil {
		c.dup.Release()
		c.dup = nil
	}
	if c.ctx != nil {
		c.ctx.Release()
		c.ctx = nil
	}
	if c.device != nil {
		c.device.Release()
		c.device = nil
	}
}
