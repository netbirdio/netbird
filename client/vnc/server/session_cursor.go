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
	s.encMu.Lock()
	s.lastCursorSerial = serial
	s.encMu.Unlock()
	return buf
}

// encodeCursorPseudoRect packs the cursor sprite into a Cursor pseudo
// rectangle (RFB 7.7.4, pseudo-encoding -239). Layout: 12-byte rect header
// followed by w*h*4 BGRX pixel bytes and a 1-bit mask of (w+7)/8 bytes per
// row, MSB-first, with each row independently padded.
func encodeCursorPseudoRect(img *image.RGBA, hotX, hotY int) []byte {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	pixelBytes := w * h * 4
	maskStride := (w + 7) / 8
	maskBytes := maskStride * h
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
