//go:build !js && !ios && !android

package server

import (
	"encoding/binary"
	"image"
)

// pendingCursorRect returns the Cursor pseudo-rect for the current sprite
// when the client negotiated the encoding and the platform exposes a
// cursor source whose serial has changed since the last emission. A nil
// return means "do not include a cursor rect in this FramebufferUpdate".
func (s *session) pendingCursorRect() []byte {
	s.encMu.RLock()
	supported := s.clientSupportsCursor
	failed := s.cursorSourceFailed
	composite := s.showRemoteCursor
	lastSerial := s.lastCursorSerial
	s.encMu.RUnlock()
	if !supported || failed || composite {
		return nil
	}
	src, ok := s.capturer.(cursorSource)
	if !ok {
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
	if img == nil || serial == lastSerial {
		return nil
	}
	buf := encodeCursorPseudoRect(img, hotX, hotY)
	if buf == nil {
		return nil
	}
	// Re-check the serial under the write lock so a concurrent update
	// from another goroutine can't be silently overwritten with a stale
	// value: if someone advanced it past `serial` while we were encoding,
	// keep their value and drop this rect.
	s.encMu.Lock()
	if serial == s.lastCursorSerial {
		s.encMu.Unlock()
		return nil
	}
	if uint64(serial-s.lastCursorSerial) > 1<<63 {
		// `serial` is older than the current value (wraparound-aware
		// comparison). Drop it.
		s.encMu.Unlock()
		return nil
	}
	s.lastCursorSerial = serial
	s.encMu.Unlock()
	return buf
}

// maxCursorDim caps the cursor sprite size we'll encode. Real platform
// cursors are tiny (<=256×256 on every supported OS); a value past this
// almost certainly indicates a corrupted platform-API response, and
// blindly multiplying it into a buffer size would overflow int and produce
// an undersized allocation that the encode loop would then walk past.
const maxCursorDim = 256

// encodeCursorPseudoRect packs the cursor sprite into a Cursor pseudo
// rectangle (RFB 7.7.4, pseudo-encoding -239). Layout: 12-byte rect header
// followed by w*h*4 BGRX pixel bytes and a 1-bit mask of (w+7)/8 bytes per
// row, MSB-first, with each row independently padded. Returns nil when
// the source image's dimensions are non-positive or exceed maxCursorDim;
// callers treat nil as "skip the cursor rect this frame."
func encodeCursorPseudoRect(img *image.RGBA, hotX, hotY int) []byte {
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
	for y := 0; y < h; y++ {
		row := y * stride
		dstRow := y * w * 4
		maskRow := y * maskStride
		for x := 0; x < w; x++ {
			r := src[row+x*4+0]
			g := src[row+x*4+1]
			b := src[row+x*4+2]
			a := src[row+x*4+3]
			off := dstRow + x*4
			pix[off+0] = b
			pix[off+1] = g
			pix[off+2] = r
			pix[off+3] = 0
			if a >= 0x80 {
				mask[maskRow+x/8] |= 0x80 >> (x % 8)
			}
		}
	}
	return buf
}
