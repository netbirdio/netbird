//go:build !js && !ios && !android

package server

import (
	"fmt"
	"image"
	"io"
)

// handleShowRemoteCursor handles the NetBird-specific RFB message used by
// the dashboard to toggle "show remote cursor" mode. Wire format: 1-byte
// enable flag (0/1) plus 6 padding bytes reserved for future arguments.
func (s *session) handleShowRemoteCursor() error {
	var data [7]byte
	if _, err := io.ReadFull(s.conn, data[:]); err != nil {
		return fmt.Errorf("read showRemoteCursor: %w", err)
	}
	enable := data[0] != 0
	s.encMu.Lock()
	s.showRemoteCursor = enable
	s.encMu.Unlock()
	s.log.Debugf("show remote cursor: %v", enable)
	return nil
}

// maybeCompositeCursor blends the current server cursor into img when the
// dashboard has enabled "show remote cursor" mode. Returns silently in
// every error path: a failed compositing must not stop the regular encode
// flow.
func (s *session) maybeCompositeCursor(img *image.RGBA) {
	s.encMu.RLock()
	enabled := s.showRemoteCursor
	s.encMu.RUnlock()
	if !enabled || img == nil {
		return
	}
	src, ok := s.capturer.(cursorSource)
	if !ok {
		return
	}
	pos, ok := s.capturer.(cursorPositionSource)
	if !ok {
		return
	}
	cursorImg, hotX, hotY, _, err := src.Cursor()
	if err != nil || cursorImg == nil {
		s.cursorWarnOnce.Do(func() {
			s.log.Warnf("remote cursor unavailable: %v", err)
		})
		return
	}
	posX, posY, err := pos.CursorPos()
	if err != nil {
		s.cursorWarnOnce.Do(func() {
			s.log.Warnf("remote cursor position unavailable: %v", err)
		})
		return
	}
	compositeCursor(img, cursorImg, posX-hotX, posY-hotY)
}

// compositeCursor alpha-blends sprite onto frame at (dstX, dstY) using
// straight (non-premultiplied) alpha. Out-of-bounds destinations are
// clipped. Frames captured by our X11/Windows/macOS paths all advertise
// RGBA with a 255-only alpha channel, so the result keeps the framebuffer
// invariant ("opaque pixels everywhere") that the encoder depends on.
func compositeCursor(frame, sprite *image.RGBA, dstX, dstY int) {
	fw, fh := frame.Rect.Dx(), frame.Rect.Dy()
	sw, sh := sprite.Rect.Dx(), sprite.Rect.Dy()
	if sw == 0 || sh == 0 {
		return
	}

	x0, y0 := dstX, dstY
	x1, y1 := dstX+sw, dstY+sh
	if x0 < 0 {
		x0 = 0
	}
	if y0 < 0 {
		y0 = 0
	}
	if x1 > fw {
		x1 = fw
	}
	if y1 > fh {
		y1 = fh
	}
	if x0 >= x1 || y0 >= y1 {
		return
	}

	fStride := frame.Stride
	sStride := sprite.Stride
	for y := y0; y < y1; y++ {
		sy := y - dstY
		fbRow := y * fStride
		sRow := sy * sStride
		for x := x0; x < x1; x++ {
			sx := x - dstX
			fbOff := fbRow + x*4
			sOff := sRow + sx*4
			a := uint32(sprite.Pix[sOff+3])
			if a == 0 {
				continue
			}
			if a == 255 {
				frame.Pix[fbOff+0] = sprite.Pix[sOff+0]
				frame.Pix[fbOff+1] = sprite.Pix[sOff+1]
				frame.Pix[fbOff+2] = sprite.Pix[sOff+2]
				continue
			}
			inv := 255 - a
			frame.Pix[fbOff+0] = byte((uint32(sprite.Pix[sOff+0])*a + uint32(frame.Pix[fbOff+0])*inv) / 255)
			frame.Pix[fbOff+1] = byte((uint32(sprite.Pix[sOff+1])*a + uint32(frame.Pix[fbOff+1])*inv) / 255)
			frame.Pix[fbOff+2] = byte((uint32(sprite.Pix[sOff+2])*a + uint32(frame.Pix[fbOff+2])*inv) / 255)
		}
	}
}
