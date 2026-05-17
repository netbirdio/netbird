//go:build !js && !ios && !android

package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"time"
)

// encoderLoop owns the capture → diff → encode → write pipeline. Running it
// off the read loop prevents a slow encode (zlib full-frame, many dirty
// tiles) from blocking inbound input events.
func (s *session) encoderLoop(done chan<- struct{}) {
	defer close(done)
	for req := range s.encodeCh {
		if err := s.processFBRequest(req); err != nil {
			s.log.Debugf("encode: %v", err)
			// On write/capture error, close the connection so messageLoop
			// exits and the session terminates cleanly.
			s.conn.Close()
			drainRequests(s.encodeCh)
			return
		}
	}
}

func (s *session) processFBRequest(req fbRequest) error {
	// Watch for resolution changes between cycles. When the capturer
	// reports a new size, tell the client via DesktopSize so it can
	// reallocate its backing buffer; the next full update will then fill
	// the new dimensions. Clients that didn't advertise support are stuck
	// with the original handshake size and just see clipping on resize.
	if err := s.handleResize(); err != nil {
		return err
	}

	img, err := s.captureFrame()
	if errors.Is(err, errFrameUnchanged) {
		// macOS hashes the raw capture bytes and short-circuits when the
		// screen is byte-identical. Treat as "no dirty rects" to skip the
		// diff and send an empty update.
		s.idleFrames++
		delay := min(s.idleFrames*5, 100)
		time.Sleep(time.Duration(delay) * time.Millisecond)
		return s.sendEmptyUpdate()
	}
	if err != nil {
		// Capture failures are transient on Windows: a Ctrl+Alt+Del or
		// sign-out switches the OS to the secure desktop, and the DXGI
		// duplicator on the previous desktop returns an error until the
		// capturer reattaches on the new desktop. On Linux the X server
		// behind a virtual session may exit and the capturer reports
		// "unavailable" on every retry tick. Don't tear down the session
		// and don't spam the log: emit one line on the first failure, then
		// throttle further "still failing" lines to once per 5 s.
		s.captureErrorLog(err)
		time.Sleep(100 * time.Millisecond)
		return s.sendEmptyUpdate()
	}
	s.captureRecovered()

	if req.incremental && s.prevFrame != nil {
		return s.processIncremental(img)
	}

	// Full update.
	s.idleFrames = 0
	if err := s.sendFullUpdate(img); err != nil {
		return err
	}
	s.swapPrevCur()
	s.refreshCopyRectIndex()
	return nil
}

// processIncremental handles the diff/encode path for a non-initial frame.
// Returns nil after writing either an empty update (no changes) or a mix of
// CopyRect moves and pixel-encoded dirty rects.
func (s *session) processIncremental(img *image.RGBA) error {
	tiles := diffTiles(s.prevFrame, img, s.serverW, s.serverH, tileSize)
	if len(tiles) == 0 {
		// Nothing changed. Back off briefly before responding to reduce
		// CPU usage when the screen is static. The client re-requests
		// immediately after receiving our empty response, so without
		// this delay we'd spin at ~1000fps checking for changes.
		s.idleFrames++
		delay := min(s.idleFrames*5, 100) // 5ms → 100ms adaptive backoff
		time.Sleep(time.Duration(delay) * time.Millisecond)
		s.swapPrevCur()
		return s.sendEmptyUpdate()
	}
	s.idleFrames = 0

	// Snapshot the dirty set before extractCopyRectTiles consumes it.
	// extract mutates in place, so without the copy we lose the
	// move-destination positions needed to incrementally update the
	// CopyRect index after the swap.
	dirty := make([][4]int, len(tiles))
	copy(dirty, tiles)

	var moves []copyRectMove
	if s.useCopyRect && s.copyRectDet != nil {
		moves, tiles = s.copyRectDet.extractCopyRectTiles(img, tiles)
	}

	rects := coalesceRects(tiles)
	if s.shouldPromoteToFullFrame(rects) && len(moves) == 0 {
		if err := s.sendFullUpdate(img); err != nil {
			return err
		}
		s.swapPrevCur()
		s.refreshCopyRectIndex()
		return nil
	}
	if err := s.sendDirtyAndMoves(img, moves, rects); err != nil {
		return err
	}
	s.swapPrevCur()
	s.updateCopyRectIndex(dirty)
	return nil
}

// captureErrorLog emits one log line on the first failure after success,
// then at most once every captureErrThrottle while the capturer keeps
// failing. The "recovered" transition is logged once when err is nil and
// captureErrSeen was set.
func (s *session) captureErrorLog(err error) {
	const captureErrThrottle = 5 * time.Second
	now := time.Now()
	if !s.captureErrSeen || now.Sub(s.captureErrLast) >= captureErrThrottle {
		s.log.Debugf("capture (transient): %v", err)
		s.captureErrLast = now
	}
	s.captureErrSeen = true
}

// captureRecovered emits a one-shot debug line when capture works again
// after a failure streak. Called by the success paths.
func (s *session) captureRecovered() {
	if s.captureErrSeen {
		s.log.Debugf("capture recovered")
		s.captureErrSeen = false
	}
}

// handleResize detects framebuffer-size changes between encode cycles and
// notifies the client via the DesktopSize pseudo-encoding. Returns an
// error only on write failure; capturers that don't expose Width/Height
// yet (zero values during early startup) are silently ignored.
func (s *session) handleResize() error {
	w, h := s.capturer.Width(), s.capturer.Height()
	if w <= 0 || h <= 0 {
		return nil
	}
	if w == s.serverW && h == s.serverH {
		return nil
	}
	s.log.Debugf("framebuffer resized: %dx%d -> %dx%d", s.serverW, s.serverH, w, h)
	s.serverW = w
	s.serverH = h
	// Drop the prev frame so the next encode produces a full update at
	// the new dimensions rather than diffing against a stale-sized buffer.
	s.prevFrame = nil
	s.curFrame = nil
	if s.copyRectDet != nil {
		// Tile geometry changed; let updateDirty rebuild from scratch on
		// the next pass instead of reusing stale hashes keyed on old
		// (cols, rows).
		s.copyRectDet.prevTiles = nil
		s.copyRectDet.tileHash = nil
	}
	if err := s.sendDesktopSize(w, h); err != nil {
		return fmt.Errorf("send desktop size: %w", err)
	}
	return nil
}

// sendDesktopSize emits a single-rect FramebufferUpdate carrying the
// DesktopSize pseudo-encoding. No-op if the client did not negotiate it,
// in which case the client just sees the new dimensions on the next full
// update and will likely clip or scale.
func (s *session) sendDesktopSize(w, h int) error {
	s.encMu.RLock()
	supported := s.clientSupportsDesktopSize || s.clientSupportsExtendedDesktopSize
	s.encMu.RUnlock()
	if !supported {
		return nil
	}
	header := make([]byte, 4)
	header[0] = serverFramebufferUpdate
	binary.BigEndian.PutUint16(header[2:4], 1)

	body := encodeDesktopSizeBody(w, h)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.conn.Write(header); err != nil {
		return err
	}
	_, err := s.conn.Write(body)
	return err
}

// refreshCopyRectIndex does a full hash sweep of the just-swapped prevFrame.
// Used after full-frame sends, where we don't have a per-tile dirty list to
// drive an incremental update.
func (s *session) refreshCopyRectIndex() {
	if s.copyRectDet == nil || s.prevFrame == nil {
		return
	}
	s.copyRectDet.rebuild(s.prevFrame, s.serverW, s.serverH)
}

// updateCopyRectIndex incrementally updates the CopyRect detector's hash
// tables for the tiles that just changed. On first use (or after resize)
// updateDirty internally falls back to a full rebuild.
func (s *session) updateCopyRectIndex(dirty [][4]int) {
	if s.copyRectDet == nil || s.prevFrame == nil {
		return
	}
	s.copyRectDet.updateDirty(s.prevFrame, s.serverW, s.serverH, dirty)
}

// captureFrame returns a session-owned frame for this encode cycle.
// Capturers that implement captureIntoer (Linux X11, macOS) write directly
// into curFrame, saving a per-frame full-screen memcpy. Capturers that
// don't (Windows DXGI) return their own buffer which we copy into curFrame
// to keep the encoder's prevFrame stable across the next capture cycle.
func (s *session) captureFrame() (*image.RGBA, error) {
	w, h := s.serverW, s.serverH
	if s.curFrame == nil || s.curFrame.Rect.Dx() != w || s.curFrame.Rect.Dy() != h {
		s.curFrame = image.NewRGBA(image.Rect(0, 0, w, h))
	}

	if ci, ok := s.capturer.(captureIntoer); ok {
		if err := ci.CaptureInto(s.curFrame); err != nil {
			return nil, err
		}
		return s.curFrame, nil
	}

	src, err := s.capturer.Capture()
	if err != nil {
		return nil, err
	}
	if s.curFrame.Rect != src.Rect {
		s.curFrame = image.NewRGBA(src.Rect)
	}
	copy(s.curFrame.Pix, src.Pix)
	return s.curFrame, nil
}

// shouldPromoteToFullFrame returns true when the dirty rect set covers a
// large enough fraction of the screen that a single full-frame zlib rect
// beats per-tile encoding on both CPU time and wire bytes. The crossover
// is measured via BenchmarkEncodeManyTilesVsFullFrame.
func (s *session) shouldPromoteToFullFrame(rects [][4]int) bool {
	if s.serverW == 0 || s.serverH == 0 {
		return false
	}
	var dirty int
	for _, r := range rects {
		dirty += r[2] * r[3]
	}
	return dirty*fullFramePromoteDen > s.serverW*s.serverH*fullFramePromoteNum
}

// swapPrevCur makes the just-encoded frame the new prevFrame (for the next
// diff) and lets the old prevFrame buffer become the next curFrame. Avoids
// an 8 MB copy per frame compared to the old savePrevFrame path.
func (s *session) swapPrevCur() {
	s.prevFrame, s.curFrame = s.curFrame, s.prevFrame
}

// sendEmptyUpdate sends a FramebufferUpdate with zero rectangles.
func (s *session) sendEmptyUpdate() error {
	var buf [4]byte
	buf[0] = serverFramebufferUpdate
	s.writeMu.Lock()
	_, err := s.conn.Write(buf[:])
	s.writeMu.Unlock()
	return err
}

func (s *session) sendFullUpdate(img *image.RGBA) error {
	w, h := s.serverW, s.serverH

	s.encMu.RLock()
	pf := s.pf
	useTight := s.useTight
	tight := s.tight
	s.encMu.RUnlock()

	if useTight && tight != nil && pfIsTightCompatible(pf) {
		// Tight encodes arbitrary sizes natively (Fill for uniform, JPEG
		// for photo-like, Basic+zlib otherwise). Wrap the rect bytes with
		// the 4-byte FramebufferUpdate header.
		rectBuf := encodeTightRect(img, pf, 0, 0, w, h, tight)
		buf := make([]byte, 4+len(rectBuf))
		buf[0] = serverFramebufferUpdate
		binary.BigEndian.PutUint16(buf[2:4], 1)
		copy(buf[4:], rectBuf)
		s.writeMu.Lock()
		_, err := s.conn.Write(buf)
		s.writeMu.Unlock()
		return err
	}

	buf := encodeRawRect(img, pf, 0, 0, w, h)
	s.writeMu.Lock()
	_, err := s.conn.Write(buf)
	s.writeMu.Unlock()
	return err
}

// sendDirtyAndMoves writes one FramebufferUpdate combining CopyRect moves
// (cheap, 16 bytes each) and pixel-encoded dirty rects. Moves come first so
// their source tiles are read from the client's pre-update framebuffer state,
// before any subsequent rect overwrites them.
func (s *session) sendDirtyAndMoves(img *image.RGBA, moves []copyRectMove, rects [][4]int) error {
	if len(moves) == 0 && len(rects) == 0 {
		return nil
	}

	total := len(moves) + len(rects)
	header := make([]byte, 4)
	header[0] = serverFramebufferUpdate
	binary.BigEndian.PutUint16(header[2:4], uint16(total))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.conn.Write(header); err != nil {
		return err
	}

	ts := tileSize
	for _, m := range moves {
		body := encodeCopyRectBody(m.srcX, m.srcY, m.dstX, m.dstY, ts, ts)
		if _, err := s.conn.Write(body); err != nil {
			return err
		}
	}

	for _, r := range rects {
		x, y, w, h := r[0], r[1], r[2], r[3]
		rectBuf := s.encodeTile(img, x, y, w, h)
		if _, err := s.conn.Write(rectBuf); err != nil {
			return err
		}
	}
	return nil
}

// encodeTile produces the on-wire rect bytes for a single dirty tile. Tight
// is the only non-Raw encoding we negotiate: uniform tiles collapse to its
// Fill subencoding (~16 bytes), photo-like rects route to JPEG, and the
// rest take the Basic+zlib path. Raw is the fallback when Tight is not
// negotiated or the negotiated pixel format is incompatible with Tight's
// mandatory 24-bit RGB TPIXEL encoding.
//
// Output omits the 4-byte FramebufferUpdate header; callers combine multiple
// tiles into one message.
func (s *session) encodeTile(img *image.RGBA, x, y, w, h int) []byte {
	s.encMu.RLock()
	pf := s.pf
	useTight := s.useTight
	tight := s.tight
	s.encMu.RUnlock()

	if useTight && tight != nil && pfIsTightCompatible(pf) {
		return encodeTightRect(img, pf, x, y, w, h, tight)
	}
	return encodeRawRect(img, pf, x, y, w, h)[4:]
}

// drainRequests consumes any pending requests so the sender's close completes
// cleanly after the encoder loop has decided to exit on error. Returns the
// number of drained requests to defeat empty-block lints; callers ignore it.
func drainRequests(ch chan fbRequest) int {
	var drained int
	for range ch {
		drained++
	}
	return drained
}

// pfIsTightCompatible reports whether the negotiated client pixel format
// matches Tight's TPIXEL constraint: standard RGB shifts (R=16, G=8, B=0).
// bpp/endianness/channel-max are already locked at SetPixelFormat time.
func pfIsTightCompatible(pf clientPixelFormat) bool {
	return pf.rShift == 16 && pf.gShift == 8 && pf.bShift == 0
}
