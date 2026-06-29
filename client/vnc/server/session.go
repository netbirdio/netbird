//go:build !js && !ios && !android

package server

import (
	"encoding/binary"
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

// handshakeDeadline bounds the RFB handshake exchange (version, security,
// ClientInit). Without it an authenticated peer can park a connection
// between the connection-header deadlines and messageLoop's own deadline,
// pinning a connSem slot.
const handshakeDeadline = 10 * time.Second

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

// bboxPromoteDensityPct collapses the coalesced rect list down to its
// bounding box when the dirty pixels occupy at least this fraction of the
// bbox. Catches the "windowed video" case where the player area dirties as
// a dense block but is split into many sibling rects by overlays or by
// non-uniform tile coverage. Sending one JPEG over the bbox beats sending
// dozens of small JPEGs that each carry their own header and Tight stream
// restart.
const (
	bboxPromoteDensityPct = 70
	// bboxPromoteMinArea avoids promoting a handful of small scattered
	// rects whose bbox would span most of the screen and pull in mostly
	// clean pixels.
	bboxPromoteMinArea = tileSize * tileSize * 16
)

type session struct {
	conn     net.Conn
	capturer ScreenCapturer
	injector InputInjector
	// serverW and serverH are the current framebuffer dimensions. The
	// encoder goroutine updates them on resize while the message loop reads
	// them for pointer scaling, so both accesses are guarded by encMu.
	serverW     int
	serverH     int
	desktopName string
	log         *log.Entry
	// viewOnly drops KeyEvent / PointerEvent (legacy + QEMU + extended)
	// without invoking the injector when the user approved the
	// connection in view-only mode. The bytes are still consumed off the
	// wire so the protocol stays in sync.
	viewOnly bool

	writeMu sync.Mutex
	// encMu guards the negotiated pixel format and encoding state below.
	// messageLoop writes these on SetPixelFormat/SetEncodings, which RFB
	// clients may send at any time after the handshake, while encoderLoop
	// reads them on every frame.
	encMu       sync.RWMutex
	pf          clientPixelFormat
	useTight    bool
	useCopyRect bool
	useZlib     bool
	useHextile  bool
	tight       *tightState
	zlib        *zlibState
	copyRectDet *copyRectDetector
	// Pseudo-encodings the client advertised support for. Updated under
	// encMu by handleSetEncodings and read by the encoder goroutine.
	clientSupportsDesktopSize         bool
	clientSupportsExtendedDesktopSize bool
	clientSupportsDesktopName         bool
	clientSupportsLastRect            bool
	clientSupportsQEMUKey             bool
	clientSupportsExtClipboard        bool
	clientSupportsCursor              bool
	// clientSupportsExtMouseButtons is set when the client advertises the
	// ExtendedMouseButtons pseudo-encoding (-316). Once the server emits
	// the ack rect, the client switches its pointer events to the 6-byte
	// extended format that carries back/forward buttons in a second mask
	// byte. Without this gate the byte after the type field would still
	// be a standard 7-bit mask and our parser must not look further.
	clientSupportsExtMouseButtons bool
	// extMouseAckSent is set once we've emitted the pseudo-rect ack that
	// flips the client into extended-pointer mode. Sticky for the
	// session because the client only needs to see it once.
	extMouseAckSent bool
	extClipCapsSent bool
	// lastCursorSerial is the serial of the cursor sprite last emitted.
	// The encoder re-queries the source each cycle and only emits when
	// the serial changes.
	lastCursorSerial uint64
	// cursorSourceFailed latches a permanent failure from the cursor
	// source so the encoder stops polling for the rest of the session.
	// Reset on SetEncodings so a reconnect can retry.
	cursorSourceFailed bool
	// showRemoteCursor switches the encoder to compositing the server
	// cursor sprite into the captured framebuffer at the remote position
	// instead of emitting the Cursor pseudo-encoding. Toggled by the
	// client via clientNetbirdShowRemoteCursor.
	showRemoteCursor bool
	// cursorWarnOnce throttles the diagnostic emitted when remote-cursor
	// compositing falls back to a no-op (capturer cannot supply a sprite
	// or position). One line per session is enough to point at the cause.
	cursorWarnOnce sync.Once
	// clientJPEGQuality and clientZlibLevel hold the 0..9 levels the client
	// advertised via the QualityLevel / CompressLevel pseudo-encodings, or
	// -1 when the client has not expressed a preference. Applied to the
	// tight encoder state after every SetEncodings.
	clientJPEGQuality int
	clientZlibLevel   int
	// prevFrame, curFrame and idleFrames live on the encoder goroutine and
	// must not be touched elsewhere. curFrame holds a session-owned copy of
	// the capturer's latest frame so the encoder works on a stable buffer
	// even when the capturer double-buffers and recycles memory underneath.
	prevFrame  *image.RGBA
	curFrame   *image.RGBA
	idleFrames int

	// captureErrLast throttles "capture (transient)" logs while the
	// capturer is in a sustained failure state (e.g. X server died but a
	// client is still connected). Owned by the encoder goroutine.
	captureErrLast time.Time
	captureErrSeen bool

	// encodeCh carries framebuffer-update requests from the read loop to the
	// encoder goroutine. Buffered size 1: RFB clients have one outstanding
	// request at a time, so a new request always replaces any pending one.
	encodeCh chan fbRequest

	// pointerMu guards the cached last cursor position used by
	// releaseStickyInput so the disconnect-time button-release event
	// targets the cursor's current spot instead of warping to (0, 0).
	pointerMu    sync.Mutex
	lastPointerX int
	lastPointerY int
}

type fbRequest struct {
	incremental bool
}

func (s *session) addr() string { return s.conn.RemoteAddr().String() }

// serve runs the full RFB session lifecycle.
func (s *session) serve() {
	defer s.conn.Close()
	s.pf = defaultClientPixelFormat()
	s.clientJPEGQuality = -1
	s.clientZlibLevel = -1
	s.encodeCh = make(chan fbRequest, 1)

	if err := s.handshake(); err != nil {
		s.log.Warnf("handshake with %s: %v", s.addr(), err)
		return
	}
	s.log.Infof("client connected: %s", s.addr())

	// View-only clients can't move the pointer, so default to compositing
	// the host cursor into the framebuffer. The client can still send
	// ShowRemoteCursor to turn it off.
	if s.viewOnly {
		s.encMu.Lock()
		s.showRemoteCursor = true
		s.encMu.Unlock()
	}

	// On any exit path (clean disconnect, transport error, panic) release
	// modifier keys and mouse buttons so the host doesn't end up with
	// Shift/Ctrl/Alt or a mouse button stuck because the client dropped
	// while holding them.
	defer s.releaseStickyInput()

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

func (s *session) handshake() error {
	if err := s.conn.SetDeadline(time.Now().Add(handshakeDeadline)); err != nil {
		return fmt.Errorf("set handshake deadline: %w", err)
	}
	defer s.conn.SetDeadline(time.Time{}) //nolint:errcheck

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
// control happen in the NetBird connection header (Noise_IK handshake,
// mode, username) that precedes the RFB handshake; the protocol-level
// password scheme is not supported.
func (s *session) sendSecurityTypes() error {
	if _, err := s.conn.Write([]byte{1, secNone}); err != nil {
		return err
	}
	return nil
}

func (s *session) handleSecurity(secType byte) error {
	if secType != secNone {
		return fmt.Errorf("unsupported security type: %d", secType)
	}
	return binary.Write(s.conn, binary.BigEndian, uint32(0))
}

// ViewOnlyDesktopNamePrefix tags the RFB desktop name when the host
// approved the connection in view-only mode, so a NetBird-aware client
// can switch its UI into read-only state. NUL framing guarantees no
// collision with a user-set name.
const ViewOnlyDesktopNamePrefix = "\x00NB-VIEW-ONLY\x00"

func (s *session) sendServerInit() error {
	desktop := s.desktopName
	if desktop == "" {
		desktop = "NetBird VNC"
	}
	if s.viewOnly {
		desktop = ViewOnlyDesktopNamePrefix + desktop
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

	if _, err := s.conn.Write(buf); err != nil {
		return err
	}
	return nil
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
		case clientNetbirdShowRemoteCursor:
			err = s.handleShowRemoteCursor()
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

	encs, sendExtClipCaps, sendExtMouseAck := s.applyEncodings(buf, int(numEnc))
	if len(encs) > 0 {
		s.log.Debugf("client supports encodings: %s", strings.Join(encs, ", "))
	}
	if sendExtClipCaps {
		if err := s.writeExtClipMessage(buildExtClipCaps()); err != nil {
			return fmt.Errorf("send ext clipboard caps: %w", err)
		}
	}
	if sendExtMouseAck {
		if err := s.sendExtMouseAck(); err != nil {
			return fmt.Errorf("send ext mouse ack: %w", err)
		}
	}
	return nil
}

// applyEncodings parses the SetEncodings body, updates capability flags,
// rebuilds the tight state if quality/level changed, and reports which
// one-shot acknowledgements still need to be sent.
func (s *session) applyEncodings(buf []byte, numEnc int) (names []string, sendExtClipCaps, sendExtMouseAck bool) {
	s.encMu.Lock()
	defer s.encMu.Unlock()
	// Per RFC 6143 §7.5.3 each SetEncodings replaces the previous list, so
	// reset all flags before re-applying. extClipCapsSent stays sticky so
	// we don't re-emit Caps every refresh.
	s.resetEncodingCaps()
	for i := range numEnc {
		enc := int32(binary.BigEndian.Uint32(buf[i*4 : i*4+4]))
		if name := s.applyEncoding(enc); name != "" {
			names = append(names, name)
		}
	}
	s.refreshTightStateLocked()
	sendExtClipCaps = s.clientSupportsExtClipboard && !s.extClipCapsSent
	if sendExtClipCaps {
		s.extClipCapsSent = true
	}
	sendExtMouseAck = s.clientSupportsExtMouseButtons && !s.extMouseAckSent
	if sendExtMouseAck {
		s.extMouseAckSent = true
	}
	return names, sendExtClipCaps, sendExtMouseAck
}

// refreshTightStateLocked reallocates s.tight when the requested quality
// or compression level no longer matches the cached state. Caller holds
// s.encMu.
func (s *session) refreshTightStateLocked() {
	if !s.useTight {
		return
	}
	if s.tight != nil &&
		s.tight.qualityLevel == s.clientJPEGQuality &&
		s.tight.compressLevel == s.clientZlibLevel {
		return
	}
	// When we replace an in-use tightState the client's stream-0
	// inflater carries dictionary state from the old deflater. Carry
	// the pending-reset flag so the next Basic rect tells the client
	// to reset its inflater before decoding.
	replacing := s.tight != nil
	s.tight = newTightStateWithLevels(s.clientJPEGQuality, s.clientZlibLevel)
	if replacing {
		s.tight.pendingZlibReset = true
	}
}

// resetEncodingCaps zeroes the encoding capability flags so the next pass
// through applyEncoding reflects exactly what the client just advertised.
// Caller holds s.encMu. tight / copyRectDet allocations are kept; their
// runtime use is gated by the boolean flags here.
func (s *session) resetEncodingCaps() {
	s.useTight = false
	s.useCopyRect = false
	s.useZlib = false
	s.useHextile = false
	s.clientSupportsDesktopSize = false
	s.clientSupportsExtendedDesktopSize = false
	s.clientSupportsDesktopName = false
	s.clientSupportsLastRect = false
	s.clientSupportsQEMUKey = false
	s.clientSupportsExtClipboard = false
	s.clientSupportsCursor = false
	s.clientSupportsExtMouseButtons = false
	s.cursorSourceFailed = false
	s.clientJPEGQuality = -1
	s.clientZlibLevel = -1
}

// applyEncoding records a single encoding/pseudo-encoding from a SetEncodings
// message. Returns the short name used in the debug log, or "" if the value
// is one we don't recognise. Caller holds s.encMu.
func (s *session) applyEncoding(enc int32) string {
	switch enc {
	case encCopyRect:
		s.useCopyRect = true
		if s.copyRectDet == nil {
			s.copyRectDet = newCopyRectDetector(tileSize)
		}
		return "copyrect"
	case pseudoEncDesktopSize:
		s.clientSupportsDesktopSize = true
		return "desktop-size"
	case pseudoEncExtendedDesktopSize:
		s.clientSupportsExtendedDesktopSize = true
		return "ext-desktop-size"
	case pseudoEncDesktopName:
		s.clientSupportsDesktopName = true
		return "desktop-name"
	case pseudoEncLastRect:
		s.clientSupportsLastRect = true
		return "last-rect"
	case pseudoEncQEMUExtendedKeyEvent:
		s.clientSupportsQEMUKey = true
		return "qemu-key"
	case pseudoEncExtendedClipboard:
		s.clientSupportsExtClipboard = true
		return "ext-clipboard"
	case pseudoEncCursor:
		s.clientSupportsCursor = true
		return "cursor"
	case pseudoEncExtendedMouseButtons:
		s.clientSupportsExtMouseButtons = true
		return "ext-mouse-buttons"
	case encTight:
		s.useTight = true
		return "tight"
	case encZlib:
		s.useZlib = true
		if s.zlib == nil {
			s.zlib = newZlibStateLevel(zlibLevelFor(-1))
		}
		return "zlib"
	case encHextile:
		s.useHextile = true
		return "hextile"
	}
	if enc >= pseudoEncQualityLevelMin && enc <= pseudoEncQualityLevelMax {
		s.clientJPEGQuality = int(enc - pseudoEncQualityLevelMin)
		return fmt.Sprintf("quality=%d", s.clientJPEGQuality)
	}
	if enc >= pseudoEncCompressLevelMin && enc <= pseudoEncCompressLevelMax {
		s.clientZlibLevel = int(enc - pseudoEncCompressLevelMin)
		return fmt.Sprintf("compress=%d", s.clientZlibLevel)
	}
	return ""
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

func (s *session) handleKeyEvent() error {
	var data [7]byte
	if _, err := io.ReadFull(s.conn, data[:]); err != nil {
		return fmt.Errorf("read KeyEvent: %w", err)
	}
	if s.viewOnly {
		return nil
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
	if s.viewOnly {
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
	mask := uint16(data[0])
	x := int(binary.BigEndian.Uint16(data[1:3]))
	y := int(binary.BigEndian.Uint16(data[3:5]))

	s.encMu.RLock()
	extended := s.clientSupportsExtMouseButtons && s.extMouseAckSent
	s.encMu.RUnlock()
	if extended && mask&0x80 != 0 {
		var hi [1]byte
		if _, err := io.ReadFull(s.conn, hi[:]); err != nil {
			return fmt.Errorf("read ExtendedPointerEvent tail: %w", err)
		}
		// Strip the marker bit; bits 0..6 are the low part of the mask,
		// hi byte holds bits 7..14 (back at bit 7, forward at bit 8).
		mask = (mask & 0x7f) | uint16(hi[0])<<7
	}

	if s.viewOnly {
		return nil
	}
	s.pointerMu.Lock()
	s.lastPointerX = x
	s.lastPointerY = y
	s.pointerMu.Unlock()
	s.encMu.RLock()
	w, h := s.serverW, s.serverH
	s.encMu.RUnlock()
	s.injector.InjectPointer(mask, x, y, w, h)
	return nil
}

// stickyModifierKeysyms are the X11 keysyms we send "up" events for on
// disconnect. Modifier-up while not held is a no-op on every supported
// platform, so we can blanket-release without per-key tracking. This
// covers the practical sticky-state bug: client drops while user is
// holding Shift / Ctrl / Alt / Meta / Super.
var stickyModifierKeysyms = [...]uint32{
	0xffe1, 0xffe2, // Shift_L, Shift_R
	0xffe3, 0xffe4, // Control_L, Control_R
	0xffe9, 0xffea, // Alt_L, Alt_R
	0xffe7, 0xffe8, // Meta_L, Meta_R
	0xffeb, 0xffec, // Super_L, Super_R
	0xff7e, // Mode_switch
	0xfe03, // ISO_Level3_Shift (AltGr)
	0xffe5, // Caps_Lock (release if user dropped mid-press)
}

// releaseStickyInput synthesizes key-up for modifier keysyms and a
// zero-button PointerEvent so the host doesn't end up with stuck input
// when the client disconnects mid-press. Mouse coordinates are reused
// from the last PointerEvent so we don't warp the cursor.
func (s *session) releaseStickyInput() {
	if s.viewOnly {
		return
	}
	for _, ks := range stickyModifierKeysyms {
		s.injector.InjectKey(ks, false)
	}
	s.pointerMu.Lock()
	x, y := s.lastPointerX, s.lastPointerY
	s.pointerMu.Unlock()
	s.encMu.RLock()
	w, h := s.serverW, s.serverH
	s.encMu.RUnlock()
	s.injector.InjectPointer(0, x, y, w, h)
}
