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
//
// Per-request panics are caught and turned into session teardown so a bug
// in one encoder path (a malformed capture frame, a zlib corner case) can
// only kill its own session, never the whole VNC server.
func (s *session) encoderLoop(done chan<- struct{}) {
	defer close(done)
	for req := range s.encodeCh {
		err := s.processFBRequestSafe(req)
		if err != nil {
			s.log.Debugf("encode: %v", err)
			// On write/capture error, close the connection so messageLoop
			// exits and the session terminates cleanly.
			s.conn.Close()
			drainRequests(s.encodeCh)
			return
		}
	}
}

// processFBRequestSafe wraps processFBRequest with a panic recover so a
// crash in encode/diff/compress paths surfaces as a session-only error
// instead of bringing down every peer's VNC sessions. The recover handler
// avoids any further dereference of session state (the panic itself may
// indicate a half-initialised session) so it can never re-panic.
func (s *session) processFBRequestSafe(req fbRequest) (err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		err = fmt.Errorf("encoder panic: %v", r)
		if s != nil && s.log != nil {
			s.log.Errorf("encoder panic recovered: %v", r)
		}
	}()
	return s.processFBRequest(req)
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

	busy := s.applyBackpressure()
	if busy >= backpressureSkipThreshold {
		return s.sendEmptyUpdate()
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

	s.maybeCompositeCursor(img)

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
	if len(moves) == 0 {
		if bb, ok := promoteToBoundingBox(rects); ok {
			rects = bb
		}
	}
	if err := s.sendDirtyAndMoves(img, moves, rects); err != nil {
		return err
	}
	s.swapPrevCur()
	s.updateCopyRectIndex(dirty)
	return nil
}

// backpressureSkipThreshold is the BusyFraction at and above which we drop
// the next encode entirely and respond with an empty FramebufferUpdate.
// Above this level the encoder would only stack more bytes behind a socket
// that is already write-blocked, raising end-to-end latency.
const backpressureSkipThreshold = 0.65

// backpressureRampStart is where adaptive quality begins clipping. Below
// this fraction the honoured client quality is used as-is.
const backpressureRampStart = 0.2

// backpressureMinQuality is the floor JPEG quality picked when the socket
// is fully saturated short of the skip threshold.
const backpressureMinQuality = 25

// applyBackpressure samples the socket BusyFraction (if available) and, if
// Tight is in use, ramps the active JPEG quality from the client-honoured
// value down to backpressureMinQuality as the fraction climbs from
// backpressureRampStart toward backpressureSkipThreshold. Returns the
// observed fraction so the caller can decide whether to skip the frame.
func (s *session) applyBackpressure() float64 {
	type busyReporter interface{ BusyFraction() float64 }
	bs, ok := s.conn.(busyReporter)
	if !ok {
		return 0
	}
	frac := bs.BusyFraction()

	s.encMu.RLock()
	tight := s.tight
	s.encMu.RUnlock()
	if tight == nil {
		return frac
	}

	base := jpegQualityForLevel(tight.qualityLevel)
	if base == 0 {
		// No client-negotiated quality; let tightQualityFor pick the
		// area-based default and skip backpressure adjustments that
		// would otherwise lock in a wrong starting point.
		tight.jpegQualityOverride = 0
		return frac
	}
	q := base
	if frac > backpressureRampStart {
		span := backpressureSkipThreshold - backpressureRampStart
		t := (frac - backpressureRampStart) / span
		if t > 1 {
			t = 1
		}
		q = base - int(float64(base-backpressureMinQuality)*t)
		if q < backpressureMinQuality {
			q = backpressureMinQuality
		}
	}
	tight.jpegQualityOverride = q
	return frac
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
	if w > maxFramebufferDim || h > maxFramebufferDim {
		s.log.Warnf("ignoring resize: %dx%d exceeds cap %d", w, h, maxFramebufferDim)
		return nil
	}
	if w == s.serverW && h == s.serverH {
		return nil
	}
	s.log.Debugf("framebuffer resized: %dx%d -> %dx%d", s.serverW, s.serverH, w, h)
	s.encMu.Lock()
	s.serverW = w
	s.serverH = h
	s.encMu.Unlock()
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

// sendExtMouseAck emits the pseudo-rect that flips the client into
// ExtendedMouseButtons mode, where mouse-back and mouse-forward are
// carried in a second mask byte. The rect has zero geometry and no
// body; the encoding number alone is the signal.
func (s *session) sendExtMouseAck() error {
	header := make([]byte, 4)
	header[0] = serverFramebufferUpdate
	binary.BigEndian.PutUint16(header[2:4], 1)

	rect := make([]byte, 12)
	enc := int32(pseudoEncExtendedMouseButtons)
	binary.BigEndian.PutUint32(rect[8:12], uint32(enc))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.conn.Write(header); err != nil {
		return err
	}
	_, err := s.conn.Write(rect)
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

// promoteToBoundingBox replaces the rect list with a single rect covering
// the bounding box of all inputs, provided the bbox is at least
// bboxPromoteMinArea and the dirty pixels fill at least
// bboxPromoteDensityPct of it. Returns the new rect list and true when the
// promotion fires; otherwise returns nil, false and the caller keeps the
// original list.
func promoteToBoundingBox(rects [][4]int) ([][4]int, bool) {
	if len(rects) < 2 {
		return nil, false
	}
	x0, y0 := rects[0][0], rects[0][1]
	x1, y1 := x0+rects[0][2], y0+rects[0][3]
	dirty := 0
	for _, r := range rects {
		if r[0] < x0 {
			x0 = r[0]
		}
		if r[1] < y0 {
			y0 = r[1]
		}
		if r[0]+r[2] > x1 {
			x1 = r[0] + r[2]
		}
		if r[1]+r[3] > y1 {
			y1 = r[1] + r[3]
		}
		dirty += r[2] * r[3]
	}
	w, h := x1-x0, y1-y0
	bbox := w * h
	if bbox < bboxPromoteMinArea {
		return nil, false
	}
	if int64(dirty)*100 < int64(bbox)*bboxPromoteDensityPct {
		return nil, false
	}
	return [][4]int{{x0, y0, w, h}}, true
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
	return int64(dirty)*fullFramePromoteDen > int64(s.serverW)*int64(s.serverH)*fullFramePromoteNum
}

// swapPrevCur makes the just-encoded frame the new prevFrame (for the next
// diff) and lets the old prevFrame buffer become the next curFrame. Avoids
// an 8 MB copy per frame compared to the old savePrevFrame path.
func (s *session) swapPrevCur() {
	s.prevFrame, s.curFrame = s.curFrame, s.prevFrame
}

// sendEmptyUpdate sends a FramebufferUpdate with zero pixel rectangles.
// When the cursor source reports a fresh sprite we still slip the Cursor
// pseudo-rect into the same message so a shape change (e.g. hovering onto
// a resize handle) reaches the client without waiting for a dirty frame.
func (s *session) sendEmptyUpdate() error {
	cursorRect := s.pendingCursorRect()
	if cursorRect == nil {
		var buf [4]byte
		buf[0] = serverFramebufferUpdate
		return s.writeFramed(buf[:])
	}
	buf := make([]byte, 4+len(cursorRect))
	buf[0] = serverFramebufferUpdate
	binary.BigEndian.PutUint16(buf[2:4], 1)
	copy(buf[4:], cursorRect)
	return s.writeFramed(buf)
}

func (s *session) sendFullUpdate(img *image.RGBA) error {
	w, h := s.serverW, s.serverH

	s.encMu.RLock()
	pf := s.pf
	useTight := s.useTight
	tight := s.tight
	useZlib := s.useZlib
	zlib := s.zlib
	s.encMu.RUnlock()

	cursorRect := s.pendingCursorRect()
	rectCount := uint16(1)
	if cursorRect != nil {
		rectCount++
	}

	var rectBuf []byte
	switch {
	case useTight && tight != nil && pfIsTightCompatible(pf):
		rectBuf = encodeTightRect(img, pf, 0, 0, w, h, tight)
	case useZlib && zlib != nil:
		body, done, err := s.encodeZlibSingle(img, pf, w, h, zlib, cursorRect)
		if done {
			return err
		}
		rectBuf = body
	default:
		if cursorRect == nil {
			return s.writeFramed(encodeRawRect(img, pf, 0, 0, w, h))
		}
		rectBuf = encodeRawRect(img, pf, 0, 0, w, h)[4:]
	}

	buf := make([]byte, 4+len(cursorRect)+len(rectBuf))
	buf[0] = serverFramebufferUpdate
	binary.BigEndian.PutUint16(buf[2:4], rectCount)
	off := 4
	off += copy(buf[off:], cursorRect)
	copy(buf[off:], rectBuf)
	return s.writeFramed(buf)
}

// encodeZlibSingle encodes one full-frame rect with Zlib. When cursorRect is
// nil it writes the encodeZlibRect-baked FBU header directly and returns
// done=true with the writeFramed error. Otherwise it returns the rect body
// (header-stripped) so the caller can prepend a cursor rect. On compressor
// failure it falls back to Raw.
func (s *session) encodeZlibSingle(img *image.RGBA, pf clientPixelFormat, w, h int, zlib *zlibState, cursorRect []byte) (body []byte, done bool, err error) {
	if zb, ok := encodeZlibRect(img, pf, 0, 0, w, h, zlib); ok {
		if cursorRect == nil {
			if werr := s.writeFramed(zb); werr != nil {
				return nil, true, werr
			}
			return nil, true, nil
		}
		return zb[4:], false, nil
	}
	if cursorRect == nil {
		if werr := s.writeFramed(encodeRawRect(img, pf, 0, 0, w, h)); werr != nil {
			return nil, true, werr
		}
		return nil, true, nil
	}
	return encodeRawRect(img, pf, 0, 0, w, h)[4:], false, nil
}

func (s *session) writeFramed(buf []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.conn.Write(buf); err != nil {
		return err
	}
	return nil
}

// sendDirtyAndMoves writes one FramebufferUpdate combining CopyRect moves
// (cheap, 16 bytes each) and pixel-encoded dirty rects. Moves come first so
// their source tiles are read from the client's pre-update framebuffer state,
// before any subsequent rect overwrites them.
func (s *session) sendDirtyAndMoves(img *image.RGBA, moves []copyRectMove, rects [][4]int) error {
	cursorRect := s.pendingCursorRect()
	if len(moves) == 0 && len(rects) == 0 && cursorRect == nil {
		return nil
	}

	total := len(moves) + len(rects)
	if cursorRect != nil {
		total++
	}
	header := make([]byte, 4)
	header[0] = serverFramebufferUpdate
	binary.BigEndian.PutUint16(header[2:4], uint16(total))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.conn.Write(header); err != nil {
		return err
	}

	if cursorRect != nil {
		if _, err := s.conn.Write(cursorRect); err != nil {
			return err
		}
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
	useHextile := s.useHextile
	useTight := s.useTight
	tight := s.tight
	useZlib := s.useZlib
	zlib := s.zlib
	s.encMu.RUnlock()

	if useHextile {
		if pixel, uniform := tileIsUniform(img, x, y, w, h); uniform {
			r := byte(pixel)
			g := byte(pixel >> 8)
			b := byte(pixel >> 16)
			return encodeHextileSolidRect(r, g, b, pf, rect{x, y, w, h})
		}
	}
	if useTight && tight != nil && pfIsTightCompatible(pf) {
		return encodeTightRect(img, pf, x, y, w, h, tight)
	}
	if useZlib && zlib != nil {
		if zb, ok := encodeZlibRect(img, pf, x, y, w, h, zlib); ok {
			return zb[4:]
		}
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
// satisfies Tight's TPIXEL constraint (RFB 7.7.6): the three RGB shifts form
// a permutation of {0, 8, 16} so the colour values live in the low 24 bits.
// bpp, endianness, and 8-bit channels are already enforced at SetPixelFormat
// time. Any permutation works because Tight always emits a three-byte R, G,
// B triple regardless of where the client stores each channel.
func pfIsTightCompatible(pf clientPixelFormat) bool {
	shifts := uint32(1)<<pf.rShift | uint32(1)<<pf.gShift | uint32(1)<<pf.bShift
	return shifts == 1<<0|1<<8|1<<16
}
