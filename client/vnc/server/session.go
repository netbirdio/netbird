package server

import (
	"bytes"
	"crypto/rand"
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
	conn     net.Conn
	capturer ScreenCapturer
	injector InputInjector
	serverW  int
	serverH  int
	password string
	log      *log.Entry

	writeMu sync.Mutex
	// pf and useZlib/zlib are written by messageLoop before the first FB
	// update request arrives (SetPixelFormat/SetEncodings happen during the
	// client handshake), and only read from the encoder goroutine. Fine
	// without locks because of that ordering invariant.
	pf         clientPixelFormat
	useZlib    bool
	useHextile bool
	useTight   bool
	zlib       *zlibState
	tight      *tightState
	// prevFrame, curFrame and idleFrames live on the encoder goroutine and
	// must not be touched elsewhere. curFrame holds a session-owned copy of
	// the capturer's latest frame so the encoder works on a stable buffer
	// even when the capturer double-buffers and recycles memory underneath.
	prevFrame  *image.RGBA
	curFrame   *image.RGBA
	idleFrames int

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
			if text != "" && text != lastClip {
				lastClip = text
				if err := s.sendServerCutText(text); err != nil {
					s.log.Debugf("send clipboard to client: %v", err)
					return
				}
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

func (s *session) sendSecurityTypes() error {
	if s.password == "" {
		_, err := s.conn.Write([]byte{1, secNone})
		return err
	}
	_, err := s.conn.Write([]byte{1, secVNCAuth})
	return err
}

func (s *session) handleSecurity(secType byte) error {
	switch secType {
	case secVNCAuth:
		return s.doVNCAuth()
	case secNone:
		return binary.Write(s.conn, binary.BigEndian, uint32(0))
	default:
		return fmt.Errorf("unsupported security type: %d", secType)
	}
}

func (s *session) doVNCAuth() error {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("generate challenge: %w", err)
	}
	if _, err := s.conn.Write(challenge); err != nil {
		return fmt.Errorf("send challenge: %w", err)
	}

	response := make([]byte, 16)
	if _, err := io.ReadFull(s.conn, response); err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	var result uint32
	if s.password != "" {
		expected, err := vncAuthEncrypt(challenge, s.password)
		if err != nil {
			return fmt.Errorf("vnc auth encrypt: %w", err)
		}
		if !bytes.Equal(expected, response) {
			result = 1
		}
	}

	if err := binary.Write(s.conn, binary.BigEndian, result); err != nil {
		return fmt.Errorf("send auth result: %w", err)
	}
	if result != 0 {
		msg := "authentication failed"
		_ = binary.Write(s.conn, binary.BigEndian, uint32(len(msg)))
		_, _ = s.conn.Write([]byte(msg))
		return fmt.Errorf("authentication failed from %s", s.addr())
	}
	return nil
}

func (s *session) sendServerInit() error {
	name := []byte("NetBird VNC")
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
	s.pf = parsePixelFormat(buf[3:19])
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
	for i := range int(numEnc) {
		enc := int32(binary.BigEndian.Uint32(buf[i*4 : i*4+4]))
		switch enc {
		case encZlib:
			s.useZlib = true
			if s.zlib == nil {
				s.zlib = newZlibState()
			}
			encs = append(encs, "zlib")
		case encHextile:
			s.useHextile = true
			encs = append(encs, "hextile")
		case encTight:
			s.useTight = true
			if s.tight == nil {
				s.tight = newTightState()
			}
			encs = append(encs, "tight")
		}
	}
	if len(encs) > 0 {
		s.log.Debugf("client supports encodings: %s", strings.Join(encs, ", "))
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
		// capturer reattaches on the new desktop. Don't tear down the
		// session. Back off briefly and reply with an empty update so
		// the client keeps re-requesting.
		s.log.Debugf("capture (transient): %v", err)
		time.Sleep(100 * time.Millisecond)
		return s.sendEmptyUpdate()
	}

	if req.incremental && s.prevFrame != nil {
		rects := diffRects(s.prevFrame, img, s.serverW, s.serverH, tileSize)
		if len(rects) == 0 {
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
		if s.shouldPromoteToFullFrame(rects) {
			if err := s.sendFullUpdate(img); err != nil {
				return err
			}
			s.swapPrevCur()
			return nil
		}
		if err := s.sendDirtyRects(img, rects); err != nil {
			return err
		}
		s.swapPrevCur()
		return nil
	}

	// Full update.
	s.idleFrames = 0
	if err := s.sendFullUpdate(img); err != nil {
		return err
	}
	s.swapPrevCur()
	return nil
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

	var buf []byte
	if s.useZlib && s.zlib != nil {
		buf = encodeZlibRect(img, s.pf, 0, 0, w, h, s.zlib)
	} else {
		buf = encodeRawRect(img, s.pf, 0, 0, w, h)
	}

	s.writeMu.Lock()
	_, err := s.conn.Write(buf)
	s.writeMu.Unlock()
	return err
}

func (s *session) sendDirtyRects(img *image.RGBA, rects [][4]int) error {
	// Build a multi-rectangle FramebufferUpdate.
	// Header: type(1) + padding(1) + numRects(2)
	header := make([]byte, 4)
	header[0] = serverFramebufferUpdate
	binary.BigEndian.PutUint16(header[2:4], uint16(len(rects)))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.conn.Write(header); err != nil {
		return err
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

// encodeTile produces the on-wire rect bytes for a single dirty tile,
// picking the cheapest encoding available:
//   - Hextile SolidFill when the tile is a single colour (~20 bytes for a
//     64×64 tile instead of ~1-2 KB zlib, ~16 KB raw).
//   - Zlib when the client negotiated it.
//   - Raw otherwise.
//
// Output omits the 4-byte FramebufferUpdate header; callers combine multiple
// tiles into one message.
func (s *session) encodeTile(img *image.RGBA, x, y, w, h int) []byte {
	if s.useHextile {
		if pixel, uniform := tileIsUniform(img, x, y, w, h); uniform {
			r := byte(pixel)
			g := byte(pixel >> 8)
			b := byte(pixel >> 16)
			return encodeHextileSolidRect(r, g, b, s.pf, rect{x, y, w, h})
		}
		// Full Hextile encoder disabled pending investigation of 16×16
		// red-tile artifacts on Windows. Solid-fill fast path is safe.
	}
	// Larger merged rects: prefer Tight (JPEG for photo-like, Basic+zlib
	// otherwise) when the client supports it AND the negotiated format is
	// compatible with Tight's mandatory 24-bit RGB TPIXEL encoding. Tight is
	// dramatically better than RFB Zlib on photographic content and
	// competitive on UI.
	if s.useTight && s.tight != nil && pfIsTightCompatible(s.pf) {
		return encodeTightRect(img, s.pf, x, y, w, h, s.tight)
	}
	if s.useZlib && s.zlib != nil {
		return encodeZlibRect(img, s.pf, x, y, w, h, s.zlib)[4:]
	}
	return encodeRawRect(img, s.pf, x, y, w, h)[4:]
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
	length := binary.BigEndian.Uint32(header[3:7])
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
// matches Tight's TPIXEL constraint: 32 bpp true colour with 8-bit RGB
// channels at standard shifts (R=16, G=8, B=0). For anything else we fall
// back to Zlib/Hextile/Raw which respect pf in full.
func pfIsTightCompatible(pf clientPixelFormat) bool {
	return pf.bpp == 32 &&
		pf.rMax == 255 && pf.gMax == 255 && pf.bMax == 255 &&
		pf.rShift == 16 && pf.gShift == 8 && pf.bShift == 0
}
