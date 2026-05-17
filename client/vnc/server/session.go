//go:build !js && !ios && !android

package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	readDeadline    = 60 * time.Second
	maxCutTextBytes = 1 << 20 // 1 MiB
)

const tileSize = 64 // pixels per tile for dirty-rect detection

// fullFramePromoteNum/Den trigger full-frame encoding when the dirty area
// exceeds num/den of the screen. Once past the crossover (benchmarks put it
// around 60% at 1080p) a single zlib rect is faster than many per-tile
// encodes AND produces about the same wire bytes: the per-tile path keeps
// restarting zlib dictionaries and re-emitting rect headers.
const (
	fullFramePromoteNum = 60
	fullFramePromoteDen = 100
)

type session struct {
	conn        net.Conn
	capturer    ScreenCapturer
	injector    InputInjector
	serverW     int
	serverH     int
	desktopName string
	log         *log.Entry

	writeMu sync.Mutex
	// encMu guards the negotiated pixel format and encoding state below.
	// messageLoop writes these on SetPixelFormat/SetEncodings, which RFB
	// clients may send at any time after the handshake, while encoderLoop
	// reads them on every frame.
	encMu       sync.RWMutex
	pf          clientPixelFormat
	useTight    bool
	useCopyRect bool
	tight       *tightState
	copyRectDet *copyRectDetector
	// Pseudo-encodings the client advertised support for. Updated under
	// encMu by handleSetEncodings and read by the encoder goroutine.
	clientSupportsDesktopSize         bool
	clientSupportsExtendedDesktopSize bool
	clientSupportsDesktopName         bool
	clientSupportsLastRect            bool
	clientSupportsQEMUKey             bool
	clientSupportsExtClipboard        bool
	extClipCapsSent                   bool
	// prevFrame, curFrame and idleFrames live on the encoder goroutine and
	// must not be touched elsewhere. curFrame holds a session-owned copy of
	// the capturer's latest frame so the encoder works on a stable buffer
	// even when the capturer double-buffers and recycles memory underneath.
	prevFrame  *image.RGBA
	curFrame   *image.RGBA
	idleFrames int

	// captureErrLast throttles "capture (transient)" logs while the
	// capturer is in a sustained failure state (e.g. X server died but a
	// noVNC tab is still open). Owned by the encoder goroutine.
	captureErrLast time.Time
	captureErrSeen bool

	// encodeCh carries framebuffer-update requests from the read loop to the
	// encoder goroutine. Buffered size 1: RFB clients have one outstanding
	// request at a time, so a new request always replaces any pending one.
	encodeCh chan fbRequest
}

type fbRequest struct {
	incremental bool
}

func (s *session) addr() string { return s.conn.RemoteAddr().String() }

// serve runs the full RFB session lifecycle.
func (s *session) serve() {
	defer s.conn.Close()
	s.pf = defaultClientPixelFormat()
	s.encodeCh = make(chan fbRequest, 1)

	if err := s.handshake(); err != nil {
		s.log.Warnf("handshake with %s: %v", s.addr(), err)
		return
	}
	s.log.Infof("client connected: %s", s.addr())

	done := make(chan struct{})
	defer close(done)
	go s.clipboardPoll(done)

	encoderDone := make(chan struct{})
	go s.encoderLoop(encoderDone)
	defer func() {
		close(s.encodeCh)
		<-encoderDone
	}()

	if err := s.messageLoop(); err != nil && err != io.EOF {
		s.log.Warnf("client %s disconnected: %v", s.addr(), err)
	} else {
		s.log.Infof("client disconnected: %s", s.addr())
	}
}

// clipboardPoll periodically checks the server-side clipboard and sends
// changes to the VNC client. Only runs during active sessions.
func (s *session) clipboardPoll(done <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastClip string
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			text := s.injector.GetClipboard()
			if len(text) > maxCutTextBytes {
				text = text[:maxCutTextBytes]
			}
			if text == "" || text == lastClip {
				continue
			}
			lastClip = text
			s.encMu.RLock()
			ext := s.clientSupportsExtClipboard
			s.encMu.RUnlock()
			if ext {
				if err := s.writeExtClipMessage(buildExtClipNotify(extClipFormatText)); err != nil {
					s.log.Debugf("send ext clipboard notify: %v", err)
					return
				}
			} else if err := s.sendServerCutText(text); err != nil {
				s.log.Debugf("send clipboard to client: %v", err)
				return
			}
		}
	}
}

func (s *session) handshake() error {
	// Send protocol version.
	if _, err := io.WriteString(s.conn, rfbProtocolVersion); err != nil {
		return fmt.Errorf("send version: %w", err)
	}

	// Read client version.
	var clientVer [12]byte
	if _, err := io.ReadFull(s.conn, clientVer[:]); err != nil {
		return fmt.Errorf("read client version: %w", err)
	}

	// Send supported security types.
	if err := s.sendSecurityTypes(); err != nil {
		return err
	}

	// Read chosen security type.
	var secType [1]byte
	if _, err := io.ReadFull(s.conn, secType[:]); err != nil {
		return fmt.Errorf("read security type: %w", err)
	}

	if err := s.handleSecurity(secType[0]); err != nil {
		return err
	}

	// Read ClientInit.
	var clientInit [1]byte
	if _, err := io.ReadFull(s.conn, clientInit[:]); err != nil {
		return fmt.Errorf("read ClientInit: %w", err)
	}

	return s.sendServerInit()
}

// sendSecurityTypes advertises only secNone. Authentication and access
// control are layered on top by the dashboard JWT exchange after the RFB
// handshake completes, not by the protocol-level password scheme.
func (s *session) sendSecurityTypes() error {
	_, err := s.conn.Write([]byte{1, secNone})
	return err
}

func (s *session) handleSecurity(secType byte) error {
	if secType != secNone {
		return fmt.Errorf("unsupported security type: %d", secType)
	}
	return binary.Write(s.conn, binary.BigEndian, uint32(0))
}

func (s *session) sendServerInit() error {
	desktop := s.desktopName
	if desktop == "" {
		desktop = "NetBird VNC"
	}
	name := []byte(desktop)
	buf := make([]byte, 0, 4+16+4+len(name))

	// Framebuffer width and height.
	buf = append(buf, byte(s.serverW>>8), byte(s.serverW))
	buf = append(buf, byte(s.serverH>>8), byte(s.serverH))

	// Server pixel format.
	buf = append(buf, serverPixelFormat[:]...)

	// Desktop name.
	buf = append(buf,
		byte(len(name)>>24), byte(len(name)>>16),
		byte(len(name)>>8), byte(len(name)),
	)
	buf = append(buf, name...)

	_, err := s.conn.Write(buf)
	return err
}

func (s *session) messageLoop() error {
	for {
		var msgType [1]byte
		if err := s.conn.SetDeadline(time.Now().Add(readDeadline)); err != nil {
			return fmt.Errorf("set deadline: %w", err)
		}
		if _, err := io.ReadFull(s.conn, msgType[:]); err != nil {
			return err
		}

		var err error
		switch msgType[0] {
		case clientSetPixelFormat:
			err = s.handleSetPixelFormat()
		case clientSetEncodings:
			err = s.handleSetEncodings()
		case clientFramebufferUpdateRequest:
			err = s.handleFBUpdateRequest()
		case clientKeyEvent:
			err = s.handleKeyEvent()
		case clientPointerEvent:
			err = s.handlePointerEvent()
		case clientCutText:
			err = s.handleCutText()
		case clientQEMUMessage:
			err = s.handleQEMUMessage()
		case clientNetbirdTypeText:
			err = s.handleTypeText()
		default:
			return fmt.Errorf("unknown client message type: %d", msgType[0])
		}
		// Clear the deadline only after the full message has been read and
		// processed so payload reads in the handlers stay bounded.
		_ = s.conn.SetDeadline(time.Time{})
		if err != nil {
			return err
		}
	}
}

func (s *session) handleSetPixelFormat() error {
	var buf [19]byte // 3 padding + 16 pixel format
	if _, err := io.ReadFull(s.conn, buf[:]); err != nil {
		return fmt.Errorf("read SetPixelFormat: %w", err)
	}
	pf, err := parsePixelFormat(buf[3:19])
	if err != nil {
		return err
	}
	s.encMu.Lock()
	s.pf = pf
	s.encMu.Unlock()
	return nil
}

func (s *session) handleSetEncodings() error {
	var header [3]byte // 1 padding + 2 number-of-encodings
	if _, err := io.ReadFull(s.conn, header[:]); err != nil {
		return fmt.Errorf("read SetEncodings header: %w", err)
	}
	numEnc := binary.BigEndian.Uint16(header[1:3])
	// RFB clients advertise a handful of real encodings plus pseudo-encodings.
	// Cap to keep a malicious client from forcing a 256 KiB allocation per
	// SetEncodings message.
	const maxEncodings = 64
	if numEnc > maxEncodings {
		return fmt.Errorf("SetEncodings: too many encodings (%d)", numEnc)
	}
	buf := make([]byte, int(numEnc)*4)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return err
	}

	var encs []string
	s.encMu.Lock()
	for i := range int(numEnc) {
		enc := int32(binary.BigEndian.Uint32(buf[i*4 : i*4+4]))
		switch enc {
		case encCopyRect:
			s.useCopyRect = true
			if s.copyRectDet == nil {
				s.copyRectDet = newCopyRectDetector(tileSize)
			}
			encs = append(encs, "copyrect")
		case pseudoEncDesktopSize:
			s.clientSupportsDesktopSize = true
			encs = append(encs, "desktop-size")
		case pseudoEncExtendedDesktopSize:
			s.clientSupportsExtendedDesktopSize = true
			encs = append(encs, "ext-desktop-size")
		case pseudoEncDesktopName:
			s.clientSupportsDesktopName = true
			encs = append(encs, "desktop-name")
		case pseudoEncLastRect:
			s.clientSupportsLastRect = true
			encs = append(encs, "last-rect")
		case pseudoEncQEMUExtendedKeyEvent:
			s.clientSupportsQEMUKey = true
			encs = append(encs, "qemu-key")
		case pseudoEncExtendedClipboard:
			s.clientSupportsExtClipboard = true
			encs = append(encs, "ext-clipboard")
		case encTight:
			s.useTight = true
			if s.tight == nil {
				s.tight = newTightState()
			}
			encs = append(encs, "tight")
		}
	}
	sendExtClipCaps := s.clientSupportsExtClipboard && !s.extClipCapsSent
	if sendExtClipCaps {
		s.extClipCapsSent = true
	}
	s.encMu.Unlock()
	if len(encs) > 0 {
		s.log.Debugf("client supports encodings: %s", strings.Join(encs, ", "))
	}
	if sendExtClipCaps {
		if err := s.writeExtClipMessage(buildExtClipCaps()); err != nil {
			return fmt.Errorf("send ext clipboard caps: %w", err)
		}
	}
	return nil
}

// handleFBUpdateRequest parses the request and hands it to the encoder
// goroutine. It never blocks on capture/encode, so the input dispatch loop
// stays responsive even when a previous frame is still being encoded.
func (s *session) handleFBUpdateRequest() error {
	var req [9]byte
	if _, err := io.ReadFull(s.conn, req[:]); err != nil {
		return fmt.Errorf("read FBUpdateRequest: %w", err)
	}
	r := fbRequest{incremental: req[0] == 1}
	// Channel is size 1. If a request is already pending, replace it with
	// this fresher one so the encoder always works on the latest ask.
	select {
	case s.encodeCh <- r:
	default:
		select {
		case <-s.encodeCh:
		default:
		}
		select {
		case s.encodeCh <- r:
		default:
		}
	}
	return nil
}

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

	// Full update.
	s.idleFrames = 0
	if err := s.sendFullUpdate(img); err != nil {
		return err
	}
	s.swapPrevCur()
	s.refreshCopyRectIndex()
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

// SendDesktopName pushes a DesktopName pseudo-encoded update to the
// client if it advertised support. Used by the server to keep the
// dashboard title in sync with the active session (e.g. username
// changes after login on a virtual session).
func (s *session) SendDesktopName(name string) error {
	s.encMu.RLock()
	supported := s.clientSupportsDesktopName
	s.encMu.RUnlock()
	if !supported {
		s.desktopName = name
		return nil
	}
	s.desktopName = name
	header := make([]byte, 4)
	header[0] = serverFramebufferUpdate
	binary.BigEndian.PutUint16(header[2:4], 1)

	body := encodeDesktopNameBody(name)
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

func (s *session) handleKeyEvent() error {
	var data [7]byte
	if _, err := io.ReadFull(s.conn, data[:]); err != nil {
		return fmt.Errorf("read KeyEvent: %w", err)
	}
	down := data[0] == 1
	keysym := binary.BigEndian.Uint32(data[3:7])
	s.injector.InjectKey(keysym, down)
	return nil
}

// handleQEMUMessage parses one QEMU vendor message. Today we only handle
// subtype 0 (Extended Key Event); the message itself is 12 bytes total so
// reading 11 more after the type byte covers the layout regardless of
// subtype, and unknown subtypes are dropped without aborting the session.
func (s *session) handleQEMUMessage() error {
	var data [11]byte // subtype(1) + down(2) + keysym(4) + keycode(4)
	if _, err := io.ReadFull(s.conn, data[:]); err != nil {
		return fmt.Errorf("read QEMU message: %w", err)
	}
	subtype := data[0]
	if subtype != qemuSubtypeExtendedKeyEvent {
		s.log.Tracef("ignoring QEMU subtype %d", subtype)
		return nil
	}
	down := binary.BigEndian.Uint16(data[1:3]) != 0
	keysym := binary.BigEndian.Uint32(data[3:7])
	scancode := binary.BigEndian.Uint32(data[7:11])
	s.injector.InjectKeyScancode(scancode, keysym, down)
	return nil
}

func (s *session) handlePointerEvent() error {
	var data [5]byte
	if _, err := io.ReadFull(s.conn, data[:]); err != nil {
		return fmt.Errorf("read PointerEvent: %w", err)
	}
	buttonMask := data[0]
	x := int(binary.BigEndian.Uint16(data[1:3]))
	y := int(binary.BigEndian.Uint16(data[3:5]))
	s.injector.InjectPointer(buttonMask, x, y, s.serverW, s.serverH)
	return nil
}

func (s *session) handleCutText() error {
	var header [7]byte // 3 padding + 4 length
	if _, err := io.ReadFull(s.conn, header[:]); err != nil {
		return fmt.Errorf("read CutText header: %w", err)
	}
	rawLen := int32(binary.BigEndian.Uint32(header[3:7]))
	if rawLen < 0 {
		// Negative length signals ExtendedClipboard; absolute value is the
		// payload size. Guard against MinInt32 overflow before negating.
		if rawLen == -2147483648 {
			return fmt.Errorf("ext clipboard payload too large")
		}
		return s.handleExtCutText(uint32(-rawLen))
	}
	length := uint32(rawLen)
	if length > maxCutTextBytes {
		return fmt.Errorf("cut text too large: %d bytes", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return fmt.Errorf("read CutText payload: %w", err)
	}
	s.injector.SetClipboard(string(buf))
	return nil
}

// handleExtCutText parses an ExtendedClipboard message (any of Caps,
// Notify, Request, Peek, Provide) carried as a negative-length CutText.
// Unknown actions and formats we don't handle (RTF/HTML/DIB/Files) are
// dropped without aborting the session.
func (s *session) handleExtCutText(payloadLen uint32) error {
	if payloadLen < 4 {
		return fmt.Errorf("ext clipboard payload too short: %d", payloadLen)
	}
	if payloadLen > extClipMaxPayload {
		return fmt.Errorf("ext clipboard payload too large: %d", payloadLen)
	}
	buf := make([]byte, payloadLen)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return fmt.Errorf("read ext clipboard payload: %w", err)
	}
	flags := binary.BigEndian.Uint32(buf[0:4])
	action := flags & extClipActionMask
	formats := flags & extClipFormatMask
	rest := buf[4:]

	switch action {
	case extClipActionCaps:
		// Client max sizes are informational for us today: we only emit
		// text and already cap it at extClipMaxText.
		return nil
	case extClipActionRequest:
		if formats&extClipFormatText != 0 {
			return s.sendExtClipProvideText()
		}
		return nil
	case extClipActionPeek:
		return s.writeExtClipMessage(buildExtClipNotify(extClipFormatText))
	case extClipActionNotify:
		if formats&extClipFormatText != 0 {
			return s.writeExtClipMessage(buildExtClipRequest(extClipFormatText))
		}
		return nil
	case extClipActionProvide:
		if len(rest) == 0 {
			return nil
		}
		text, err := parseExtClipProvideText(flags, rest)
		if err != nil {
			s.log.Debugf("parse ext clipboard provide: %v", err)
			return nil
		}
		if text != "" {
			s.injector.SetClipboard(text)
		}
		return nil
	default:
		s.log.Debugf("unknown ext clipboard action 0x%x", action)
		return nil
	}
}

// sendExtClipProvideText answers an inbound Request(text) with the current
// host clipboard contents, capped to extClipMaxText.
func (s *session) sendExtClipProvideText() error {
	text := s.injector.GetClipboard()
	if len(text) > extClipMaxText {
		text = text[:extClipMaxText]
	}
	payload, err := buildExtClipProvideText(text)
	if err != nil {
		return fmt.Errorf("build provide: %w", err)
	}
	return s.writeExtClipMessage(payload)
}

// writeExtClipMessage frames an ExtendedClipboard payload as a ServerCutText
// message with a negative length, then writes it under writeMu.
func (s *session) writeExtClipMessage(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	buf := make([]byte, 8+len(payload))
	buf[0] = serverCutText
	// buf[1:4] = padding (zero)
	binary.BigEndian.PutUint32(buf[4:8], uint32(-int32(len(payload))))
	copy(buf[8:], payload)

	s.writeMu.Lock()
	_, err := s.conn.Write(buf)
	s.writeMu.Unlock()
	return err
}

// handleTypeText handles the NetBird-specific PasteAndType message used by
// the dashboard's Paste button. Wire format mirrors CutText: 3-byte
// padding + 4-byte length + text bytes.
func (s *session) handleTypeText() error {
	var header [7]byte
	if _, err := io.ReadFull(s.conn, header[:]); err != nil {
		return fmt.Errorf("read TypeText header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[3:7])
	if length > maxCutTextBytes {
		return fmt.Errorf("type text too large: %d bytes", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return fmt.Errorf("read TypeText payload: %w", err)
	}
	s.injector.TypeText(string(buf))
	return nil
}

// sendServerCutText sends clipboard text from the server to the client.
func (s *session) sendServerCutText(text string) error {
	data := []byte(text)
	buf := make([]byte, 8+len(data))
	buf[0] = serverCutText
	// buf[1:4] = padding (zero)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(data)))
	copy(buf[8:], data)

	s.writeMu.Lock()
	_, err := s.conn.Write(buf)
	s.writeMu.Unlock()
	return err
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
