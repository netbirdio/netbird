//go:build !js && !ios && !android

package server

import (
	"encoding/binary"
	"fmt"
	"image"
)

// pendingCursorRect returns the Cursor pseudo-rect for the current sprite
// when the client negotiated the encoding and the platform exposes a
// cursor source whose serial has changed since the last emission. A nil
// return means "do not include a cursor rect in this FramebufferUpdate".
// pf is the format the rest of this update is being encoded in, passed in
// rather than read again here: a SetPixelFormat landing mid-update would
// otherwise pack the cursor at the new shifts and the framebuffer at the old
// ones, and the client would paint a correctly coloured desktop under a cursor
// with its channels swapped.
func (s *session) pendingCursorRect(pf clientPixelFormat) []byte {
	s.encMu.RLock()
	supported := s.clientSupportsCursor
	failed := s.cursorSourceFailed
	composite := s.showRemoteCursor
	lastSerial := s.lastCursorSerial
	s.encMu.RUnlock()
	// Each way out of here means the client gets no cursor, and they used to be
	// indistinguishable from the outside: "no cursor on this platform" looked
	// the same whether the client never asked for the encoding, the capturer
	// cannot produce one, or the sprite failed to encode. Say which, once per
	// session, so the next report of a missing cursor names its own cause.
	if !supported || failed || composite {
		s.logCursorSkip("no cursor rect: client_requested=%v source_failed=%v compositing=%v",
			supported, failed, composite)
		return nil
	}
	src, ok := s.capturer.(cursorSource)
	if !ok {
		s.logCursorSkip("no cursor rect: capturer %T reports no cursor source", s.capturer)
		return nil
	}
	img, hotX, hotY, serial, err := src.Cursor()
	if err != nil {
		s.encMu.Lock()
		s.cursorSourceFailed = true
		s.encMu.Unlock()
		s.log.Debugf("cursor source unavailable: %v", err)
		return nil
	}
	if img == nil {
		s.logCursorSkip("no cursor rect: capturer returned no sprite")
		return nil
	}
	if serial == lastSerial {
		return nil
	}
	buf := encodeCursorPseudoRect(img, hotX, hotY, pf)
	if buf == nil {
		b := img.Bounds()
		s.logCursorSkip("no cursor rect: sprite %dx%d stride=%d pix=%d could not be encoded",
			b.Dx(), b.Dy(), img.Stride, len(img.Pix))
		return nil
	}
	// Re-check under the write lock so a cursor another goroutine already
	// sent is not sent again.
	//
	// Compared for equality only, never for order. A serial identifies the
	// cursor, it does not count upwards: X11 passes through the XFixes
	// cursor-serial, which is a property of the cursor itself, so switching
	// back to a cursor shown earlier produces a *lower* value than the one on
	// screen. Treating that as stale left the client stuck on whichever cursor
	// happened to have the highest serial, typically the I-beam after a text
	// field. macOS and Windows use their own counters, which only ever move
	// forwards, so equality is the right test for all three.
	s.encMu.Lock()
	if serial == s.lastCursorSerial {
		s.encMu.Unlock()
		return nil
	}
	s.lastCursorSerial = serial
	s.encMu.Unlock()
	return buf
}

// logCursorSkip reports why this update carries no cursor rect, once per
// distinct line. pendingCursorRect runs per framebuffer update, so an
// unthrottled log would flood; throttling once per session instead would let
// whichever reason came first hide every later one, and the reasons do change
// as the client negotiates encodings and the cursor source starts failing.
func (s *session) logCursorSkip(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)

	s.cursorSkipMu.Lock()
	if s.cursorSkipSeen == nil {
		s.cursorSkipSeen = make(map[string]struct{})
	}
	_, seen := s.cursorSkipSeen[msg]
	s.cursorSkipSeen[msg] = struct{}{}
	s.cursorSkipMu.Unlock()

	if seen {
		return
	}
	s.log.Debug(msg)
}

// maxCursorDim caps the cursor sprite size we'll encode. Real platform
// cursors are tiny (<=256×256 on every supported OS); a value past this
// almost certainly indicates a corrupted platform-API response, and
// blindly multiplying it into a buffer size would overflow int and produce
// an undersized allocation that the encode loop would then walk past.
const maxCursorDim = 256

// encodeCursorPseudoRect packs the cursor sprite into a Cursor pseudo
// rectangle (RFB 7.7.4, pseudo-encoding -239). Layout: 12-byte rect header
// followed by w*h*4 pixel bytes at pf's negotiated channel shifts, then a
// 1-bit mask of (w+7)/8 bytes per row, MSB-first, with each row independently
// padded. Returns nil when
// the source image's dimensions are non-positive or exceed maxCursorDim;
// callers treat nil as "skip the cursor rect this frame."
func encodeCursorPseudoRect(img *image.RGBA, hotX, hotY int, pf clientPixelFormat) []byte {
	if img == nil {
		return nil
	}
	w, h := img.Rect.Dx(), img.Rect.Dy()
	if w <= 0 || h <= 0 || w > maxCursorDim || h > maxCursorDim {
		return nil
	}
	pixelBytes := w * h * 4
	maskStride := (w + 7) / 8
	maskBytes := maskStride * h
	// Defensive: ensure the source image is actually big enough for the
	// access pattern below. A SubImage that misreports its dx/dy would
	// otherwise be read past the end.
	if (h-1)*img.Stride+w*4 > len(img.Pix) {
		return nil
	}
	buf := make([]byte, 12+pixelBytes+maskBytes)

	binary.BigEndian.PutUint16(buf[0:2], uint16(hotX))
	binary.BigEndian.PutUint16(buf[2:4], uint16(hotY))
	binary.BigEndian.PutUint16(buf[4:6], uint16(w))
	binary.BigEndian.PutUint16(buf[6:8], uint16(h))
	enc := int32(pseudoEncCursor)
	binary.BigEndian.PutUint32(buf[8:12], uint32(enc))

	pix := buf[12 : 12+pixelBytes]
	mask := buf[12+pixelBytes:]
	src := img.Pix
	stride := img.Stride
	// Packed at the negotiated shifts, the same way writePixels packs the
	// framebuffer. Hard-coding BGRX here would leave a client that asked for
	// another channel order with a correctly coloured desktop and a cursor
	// with its red and blue swapped.
	rShift, gShift, bShift := pf.rShift, pf.gShift, pf.bShift
	for y := 0; y < h; y++ {
		row := y * stride
		dstRow := y * w * 4
		maskRow := y * maskStride
		for x := 0; x < w; x++ {
			r := src[row+x*4+0]
			g := src[row+x*4+1]
			b := src[row+x*4+2]
			a := src[row+x*4+3]
			pixel := (uint32(r) << rShift) | (uint32(g) << gShift) | (uint32(b) << bShift)
			binary.LittleEndian.PutUint32(pix[dstRow+x*4:dstRow+x*4+4], pixel)
			if a >= 0x80 {
				mask[maskRow+x/8] |= 0x80 >> (x % 8)
			}
		}
	}
	return buf
}
