//go:build (linux && !android) || freebsd

package server

import (
	"image"
	"sync"
)

// FBPoller wraps FBCapturer with the same lifecycle (ClientConnect /
// ClientDisconnect, lazy init) as X11Poller, so it slots into the same
// session plumbing without code changes upstream. The concrete
// FBCapturer is platform-specific (capture_fb_linux.go / _freebsd.go);
// this file owns the cross-platform glue.
type FBPoller struct {
	mu       sync.Mutex
	path     string
	capturer *FBCapturer
	w, h     int
	clients  int32
}

// NewFBPoller returns a poller that opens path on first use. Empty path
// defaults to /dev/fb0 on Linux and /dev/ttyv0 on FreeBSD.
func NewFBPoller(path string) *FBPoller {
	if path == "" {
		path = defaultFBPath()
	}
	return &FBPoller{path: path}
}

// ClientConnect eagerly initialises the capturer on first connect.
func (p *FBPoller) ClientConnect() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients++
	if p.clients == 1 {
		_ = p.ensureCapturerLocked()
	}
}

// ClientDisconnect closes the capturer when the last client leaves.
func (p *FBPoller) ClientDisconnect() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients--
	if p.clients <= 0 && p.capturer != nil {
		p.capturer.Close()
		p.capturer = nil
	}
}

// Width returns the framebuffer width, doing lazy init if needed.
func (p *FBPoller) Width() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.ensureCapturerLocked()
	return p.w
}

// Height returns the framebuffer height, doing lazy init if needed.
func (p *FBPoller) Height() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.ensureCapturerLocked()
	return p.h
}

// Capture takes a fresh frame.
func (p *FBPoller) Capture() (*image.RGBA, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureCapturerLocked(); err != nil {
		return nil, err
	}
	return p.capturer.Capture()
}

// CaptureInto fills dst directly.
func (p *FBPoller) CaptureInto(dst *image.RGBA) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureCapturerLocked(); err != nil {
		return err
	}
	return p.capturer.CaptureInto(dst)
}

// Close releases all framebuffer resources.
func (p *FBPoller) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.capturer != nil {
		p.capturer.Close()
		p.capturer = nil
	}
}

func (p *FBPoller) ensureCapturerLocked() error {
	if p.capturer != nil {
		return nil
	}
	c, err := NewFBCapturer(p.path)
	if err != nil {
		return err
	}
	p.capturer = c
	p.w, p.h = c.Width(), c.Height()
	return nil
}

var _ ScreenCapturer = (*FBPoller)(nil)
var _ captureIntoer = (*FBPoller)(nil)

// swizzleFB24 handles 24-bit packed framebuffers (B,G,R triplets).
// Shared between Linux and FreeBSD framebuffer paths.
func swizzleFB24(dst []byte, dstStride int, src []byte, srcStride, w, h int) {
	for y := 0; y < h; y++ {
		srcRow := src[y*srcStride : y*srcStride+w*3]
		dstRow := dst[y*dstStride:]
		for x := 0; x < w; x++ {
			b := srcRow[x*3+0]
			g := srcRow[x*3+1]
			r := srcRow[x*3+2]
			dstRow[x*4+0] = r
			dstRow[x*4+1] = g
			dstRow[x*4+2] = b
			dstRow[x*4+3] = 0xff
		}
	}
}

// swizzleFB16RGB565 handles 16bpp RGB 565 framebuffers.
func swizzleFB16RGB565(dst []byte, dstStride int, src []byte, srcStride, w, h int) {
	for y := 0; y < h; y++ {
		srcRow := src[y*srcStride : y*srcStride+w*2]
		dstRow := dst[y*dstStride:]
		for x := 0; x < w; x++ {
			pix := uint16(srcRow[x*2]) | uint16(srcRow[x*2+1])<<8
			r := byte((pix >> 11) & 0x1f)
			g := byte((pix >> 5) & 0x3f)
			b := byte(pix & 0x1f)
			dstRow[x*4+0] = (r << 3) | (r >> 2)
			dstRow[x*4+1] = (g << 2) | (g >> 4)
			dstRow[x*4+2] = (b << 3) | (b >> 2)
			dstRow[x*4+3] = 0xff
		}
	}
}
