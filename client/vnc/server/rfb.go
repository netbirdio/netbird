//go:build !js && !ios && !android

package server

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"image"
	"image/jpeg"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

// rect describes a rectangle on the framebuffer in pixels.
type rect struct {
	x, y, w, h int
}

const (
	rfbProtocolVersion = "RFB 003.008\n"

	secNone = 1

	// Client message types.
	clientSetPixelFormat           = 0
	clientSetEncodings             = 2
	clientFramebufferUpdateRequest = 3
	clientKeyEvent                 = 4
	clientPointerEvent             = 5
	clientCutText                  = 6
	// clientQEMUMessage is the QEMU vendor message wrapper. The subtype
	// byte that follows selects the actual operation; we only handle the
	// Extended Key Event (subtype 0) which carries a hardware scancode in
	// addition to the X11 keysym. Layout-independent key entry.
	clientQEMUMessage = 255

	// QEMU Extended Key Event subtype carried inside clientQEMUMessage.
	qemuSubtypeExtendedKeyEvent = 0

	// clientNetbirdTypeText is a NetBird-specific message that asks the
	// server to synthesize the given text as keystrokes regardless of the
	// active desktop. Lets a client push host clipboard content into a
	// Windows secure desktop (Winlogon, UAC), where the OS clipboard is
	// isolated. Format mirrors clientCutText: 1-byte message type + 3-byte
	// padding + 4-byte length + text bytes. The opcode is in the
	// vendor-specific range (>=128).
	clientNetbirdTypeText = 250

	// clientNetbirdShowRemoteCursor toggles "show remote cursor" mode.
	// When enabled the encoder composites the server cursor sprite into
	// the captured framebuffer and suppresses the Cursor pseudo-encoding
	// so the client sees a single pointer at the remote position.
	// Wire format: 1-byte msgType + 1-byte enable flag + 6 padding bytes
	// reserved for future arguments (so the message is fixed-size).
	clientNetbirdShowRemoteCursor = 251

	// Server message types.
	serverFramebufferUpdate = 0
	serverCutText           = 3

	// Encoding types.
	encRaw      = 0
	encCopyRect = 1
	encHextile  = 5
	encZlib     = 6
	encTight    = 7

	// Pseudo-encodings carried over wire as rects with a negative
	// encoding value. The client advertises supported optional protocol
	// extensions by listing these in SetEncodings.
	pseudoEncCursor               = -239
	pseudoEncDesktopSize          = -223
	pseudoEncLastRect             = -224
	pseudoEncQEMUExtendedKeyEvent = -258
	pseudoEncDesktopName          = -307
	pseudoEncExtendedDesktopSize  = -308
	pseudoEncExtendedMouseButtons = -316

	// Quality/Compression level pseudo-encodings. The client picks one
	// value from each range to tune JPEG quality and zlib effort. 0 is
	// lowest quality / fastest, 9 is highest quality / best compression.
	pseudoEncQualityLevelMin  = -32
	pseudoEncQualityLevelMax  = -23
	pseudoEncCompressLevelMin = -256
	pseudoEncCompressLevelMax = -247

	// Hextile sub-encoding bits used by the SolidFill fast path.
	hextileBackgroundSpecified = 0x02
	hextileSubSize             = 16

	// Tight compression-control byte top nibble. Stream-reset bits 0-3
	// (one per zlib stream) are unused while we run a single stream.
	tightFillSubenc  = 0x80
	tightJPEGSubenc  = 0x90
	tightBasicFilter = 0x40 // Bit 6 set = explicit filter byte follows.
	tightFilterCopy  = 0x00 // No-op filter, raw pixel stream.

	// JPEG quality used by the Tight encoder. 70 is a reasonable speed/
	// quality knee; bandwidth roughly halves vs raw RGB while staying
	// visually clean for typical desktop content. Large rects (e.g. a
	// fullscreen video region) drop to a lower quality so the encoder
	// keeps up at 30+ fps; the visual hit is small for moving content.
	tightJPEGQuality       = 70
	tightJPEGQualityMedium = 55
	tightJPEGQualityLarge  = 40
	tightJPEGMediumPixels  = 800 * 600  // ≈ SVGA, applies medium tier
	tightJPEGLargePixels   = 1280 * 720 // ≈ 720p, applies large tier
	// Minimum rect area before we consider JPEG. Below this, header
	// overhead dominates and Basic+zlib wins.
	tightJPEGMinArea = 4096 // 64×64 ≈ 1 tile
	// Distinct-colour cap below which we still prefer Basic+zlib (text,
	// UI). Sampled, not exhaustive: cheap to compute, good enough.
	tightJPEGMinColors = 64
)

// serverPixelFormat is the pixel format the server advertises and requires:
// 32bpp RGBA, little-endian, true-colour, 8 bits per channel at standard
// shifts (R=16, G=8, B=0). handleSetPixelFormat rejects any client that
// negotiates a different format. Browser-side decoders are little-endian
// natively, so advertising little-endian skips a byte-swap on every pixel.
var serverPixelFormat = [16]byte{
	32,     // bits-per-pixel
	24,     // depth
	0,      // big-endian-flag
	1,      // true-colour-flag
	0, 255, // red-max
	0, 255, // green-max
	0, 255, // blue-max
	16,      // red-shift
	8,       // green-shift
	0,       // blue-shift
	0, 0, 0, // padding
}

// clientPixelFormat holds the negotiated pixel format. Only RGB channel
// shifts are tracked: every other field is constrained by the server to
// the values in serverPixelFormat (32bpp / little-endian / truecolour /
// 8-bit channels) and rejected at SetPixelFormat time if the client tries
// to negotiate otherwise.
type clientPixelFormat struct {
	rShift uint8
	gShift uint8
	bShift uint8
}

func defaultClientPixelFormat() clientPixelFormat {
	return clientPixelFormat{
		rShift: serverPixelFormat[10],
		gShift: serverPixelFormat[11],
		bShift: serverPixelFormat[12],
	}
}

// parsePixelFormat returns the negotiated client pixel format, or an error
// if the client tried to negotiate an unsupported format. The server only
// supports 32bpp truecolour little-endian with 8-bit channels; arbitrary
// shifts within that constraint are allowed because they are cheap to honour.
func parsePixelFormat(pf []byte) (clientPixelFormat, error) {
	bpp := pf[0]
	bigEndian := pf[2]
	trueColour := pf[3]
	rMax := binary.BigEndian.Uint16(pf[4:6])
	gMax := binary.BigEndian.Uint16(pf[6:8])
	bMax := binary.BigEndian.Uint16(pf[8:10])
	if bpp != 32 || bigEndian != 0 || trueColour != 1 ||
		rMax != 255 || gMax != 255 || bMax != 255 {
		return clientPixelFormat{}, fmt.Errorf(
			"unsupported pixel format (bpp=%d be=%d tc=%d rgb-max=%d/%d/%d): "+
				"server only supports 32bpp truecolour little-endian 8-bit channels",
			bpp, bigEndian, trueColour, rMax, gMax, bMax)
	}
	return clientPixelFormat{
		rShift: pf[10],
		gShift: pf[11],
		bShift: pf[12],
	}, nil
}

// encodeCopyRectBody emits the per-rect payload for a CopyRect rectangle:
// the 12-byte rect header (dst position + size + encoding=1) plus a 4-byte
// source position. Used inside multi-rect FramebufferUpdate messages, so
// the 4-byte FU header is the caller's responsibility.
func encodeCopyRectBody(srcX, srcY, dstX, dstY, w, h int) []byte {
	buf := make([]byte, 12+4)
	binary.BigEndian.PutUint16(buf[0:2], uint16(dstX))
	binary.BigEndian.PutUint16(buf[2:4], uint16(dstY))
	binary.BigEndian.PutUint16(buf[4:6], uint16(w))
	binary.BigEndian.PutUint16(buf[6:8], uint16(h))
	binary.BigEndian.PutUint32(buf[8:12], uint32(encCopyRect))
	binary.BigEndian.PutUint16(buf[12:14], uint16(srcX))
	binary.BigEndian.PutUint16(buf[14:16], uint16(srcY))
	return buf
}

// encodeDesktopSizeBody emits a DesktopSize pseudo-encoded rectangle. The
// "rect" carries no pixel data: x and y are zero, w and h are the new
// framebuffer dimensions, and encoding=-223 signals to the client that the
// framebuffer was resized. Clients reallocate their backing buffer and
// expect a full update at the new size to follow.
func encodeDesktopSizeBody(w, h int) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], 0)
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint16(buf[4:6], uint16(w))
	binary.BigEndian.PutUint16(buf[6:8], uint16(h))
	enc := int32(pseudoEncDesktopSize)
	binary.BigEndian.PutUint32(buf[8:12], uint32(enc))
	return buf
}

// encodeDesktopNameBody emits a DesktopName pseudo-encoded rectangle. The
// rect header is all zeros and encoding=-307; the body is a 4-byte
// big-endian length followed by the UTF-8 name. Clients update their
// window title or label without reconnecting.
func encodeDesktopNameBody(name string) []byte {
	nameBytes := []byte(name)
	buf := make([]byte, 12+4+len(nameBytes))
	binary.BigEndian.PutUint16(buf[0:2], 0)
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint16(buf[4:6], 0)
	binary.BigEndian.PutUint16(buf[6:8], 0)
	enc := int32(pseudoEncDesktopName)
	binary.BigEndian.PutUint32(buf[8:12], uint32(enc))
	binary.BigEndian.PutUint32(buf[12:16], uint32(len(nameBytes)))
	copy(buf[16:], nameBytes)
	return buf
}

// encodeLastRectBody emits a LastRect sentinel. When the server sets
// numRects=0xFFFF in the FramebufferUpdate header, the client reads rects
// until it sees one with this encoding. Lets us stream rects from a
// goroutine without committing to a count up front.
func encodeLastRectBody() []byte {
	buf := make([]byte, 12)
	// x, y, w, h all zero; encoding = -224.
	enc := int32(pseudoEncLastRect)
	binary.BigEndian.PutUint32(buf[8:12], uint32(enc))
	return buf
}

// encodeRawRect encodes a framebuffer region as a raw RFB rectangle.
// The returned buffer includes the FramebufferUpdate header (1 rectangle).
func encodeRawRect(img *image.RGBA, pf clientPixelFormat, x, y, w, h int) []byte {
	buf := make([]byte, 4+12+w*h*4)

	// FramebufferUpdate header.
	buf[0] = serverFramebufferUpdate
	buf[1] = 0 // padding
	binary.BigEndian.PutUint16(buf[2:4], 1)

	// Rectangle header.
	binary.BigEndian.PutUint16(buf[4:6], uint16(x))
	binary.BigEndian.PutUint16(buf[6:8], uint16(y))
	binary.BigEndian.PutUint16(buf[8:10], uint16(w))
	binary.BigEndian.PutUint16(buf[10:12], uint16(h))
	binary.BigEndian.PutUint32(buf[12:16], uint32(encRaw))

	writePixels(buf[16:], img, pf, rect{x, y, w, h})
	return buf
}

// encodeZlibRect encodes a framebuffer region using the standalone Zlib
// encoding. The zlib stream is continuous for the entire VNC session: the
// client keeps a single inflate context and reuses it across rects. The
// returned buffer includes the 4-byte FramebufferUpdate header.
func encodeZlibRect(img *image.RGBA, pf clientPixelFormat, x, y, w, h int, z *zlibState) ([]byte, bool) {
	zw, zbuf := z.w, z.buf
	zbuf.Reset()

	rowBytes := w * 4
	total := rowBytes * h
	if cap(z.scratch) < total {
		z.scratch = make([]byte, total)
	}
	scratch := z.scratch[:total]
	writePixels(scratch, img, pf, rect{x, y, w, h})
	for row := 0; row < h; row++ {
		if _, err := zw.Write(scratch[row*rowBytes : (row+1)*rowBytes]); err != nil {
			log.Debugf("zlib write row %d: %v", row, err)
			return nil, false
		}
	}
	if err := zw.Flush(); err != nil {
		log.Debugf("zlib flush: %v", err)
		return nil, false
	}
	compressed := zbuf.Bytes()

	buf := make([]byte, 4+12+4+len(compressed))
	buf[0] = serverFramebufferUpdate
	binary.BigEndian.PutUint16(buf[2:4], 1)
	binary.BigEndian.PutUint16(buf[4:6], uint16(x))
	binary.BigEndian.PutUint16(buf[6:8], uint16(y))
	binary.BigEndian.PutUint16(buf[8:10], uint16(w))
	binary.BigEndian.PutUint16(buf[10:12], uint16(h))
	binary.BigEndian.PutUint32(buf[12:16], uint32(encZlib))
	binary.BigEndian.PutUint32(buf[16:20], uint32(len(compressed)))
	copy(buf[20:], compressed)
	return buf, true
}

// encodeHextileSolidRect emits a Hextile-encoded rectangle whose every
// pixel is the same colour. The first sub-tile carries the background
// pixel; remaining sub-tiles inherit it via a zero sub-encoding byte,
// collapsing a uniform 64×64 tile down to ~20 bytes. The returned buffer
// starts with the 12-byte rect header; callers prepend a FramebufferUpdate
// header.
func encodeHextileSolidRect(r, g, b byte, pf clientPixelFormat, rc rect) []byte {
	cols := (rc.w + hextileSubSize - 1) / hextileSubSize
	rows := (rc.h + hextileSubSize - 1) / hextileSubSize
	subs := cols * rows
	// One sub-encoding byte plus a 32bpp pixel for the first sub-tile, then
	// one zero byte per remaining sub-tile to inherit the background.
	bodySize := 1 + 4 + (subs - 1)
	buf := make([]byte, 12+bodySize)

	binary.BigEndian.PutUint16(buf[0:2], uint16(rc.x))
	binary.BigEndian.PutUint16(buf[2:4], uint16(rc.y))
	binary.BigEndian.PutUint16(buf[4:6], uint16(rc.w))
	binary.BigEndian.PutUint16(buf[6:8], uint16(rc.h))
	binary.BigEndian.PutUint32(buf[8:12], uint32(encHextile))

	buf[12] = hextileBackgroundSpecified
	pixel := (uint32(r) << pf.rShift) | (uint32(g) << pf.gShift) | (uint32(b) << pf.bShift)
	binary.LittleEndian.PutUint32(buf[13:17], pixel)
	return buf
}

// writePixels writes a rectangle of img into dst as 32bpp little-endian
// pixels at the negotiated RGB shifts. The pixel format is constrained at
// SetPixelFormat time so we can assume 4 bytes per pixel, 8-bit channels,
// and little-endian byte order; arbitrary shifts (R/G/B order) are honoured.
func writePixels(dst []byte, img *image.RGBA, pf clientPixelFormat, r rect) {
	stride := img.Stride
	rShift, gShift, bShift := pf.rShift, pf.gShift, pf.bShift
	off := 0
	for row := r.y; row < r.y+r.h; row++ {
		p := row*stride + r.x*4
		for col := 0; col < r.w; col++ {
			pixel := (uint32(img.Pix[p]) << rShift) |
				(uint32(img.Pix[p+1]) << gShift) |
				(uint32(img.Pix[p+2]) << bShift)
			binary.LittleEndian.PutUint32(dst[off:off+4], pixel)
			p += 4
			off += 4
		}
	}
}

// diffTiles compares two RGBA images and returns a tile-ordered list of
// dirty tiles, one entry per tile. Tile order is top-to-bottom, left-to-
// right within each row. The caller decides whether to coalesce or hand
// the list off to the CopyRect detector first.
func diffTiles(prev, cur *image.RGBA, w, h, tileSize int) [][4]int {
	if prev == nil {
		return [][4]int{{0, 0, w, h}}
	}
	var rects [][4]int
	for ty := 0; ty < h; ty += tileSize {
		th := min(tileSize, h-ty)
		for tx := 0; tx < w; tx += tileSize {
			tw := min(tileSize, w-tx)
			if tileChanged(prev, cur, tx, ty, tw, th) {
				rects = append(rects, [4]int{tx, ty, tw, th})
			}
		}
	}
	return rects
}

// diffRects is the legacy convenience: diff then coalesce. Used by paths
// that don't go through the CopyRect detector and by tests that exercise
// the diff-plus-coalesce pipeline as one unit.
func diffRects(prev, cur *image.RGBA, w, h, tileSize int) [][4]int {
	return coalesceRects(diffTiles(prev, cur, w, h, tileSize))
}

// coalesceRects merges adjacent dirty tiles into larger rectangles to cut
// per-rect framing overhead. Input must be tile-ordered (top-to-bottom rows,
// left-to-right within each row), as produced by diffRects. Two passes:
//  1. Horizontal: within a row, merge tiles whose x-extents touch.
//  2. Vertical: merge a row's run with the run directly above it when they
//     share the same [x, x+w] extent and are vertically adjacent.
//
// Larger merged rects still encode correctly: Hextile-solid and Zlib paths
// both work on arbitrary sizes, and uniform-tile detection still fires when
// the merged region happens to be a single colour.
func coalesceRects(in [][4]int) [][4]int {
	if len(in) < 2 {
		return in
	}
	c := newRectCoalescer(len(in))
	c.curY = in[0][1]
	for _, r := range in {
		c.consume(r)
	}
	c.flushCurrentRow()
	return c.out
}

// rectCoalescer is the working state for coalesceRects, lifted out so the
// algorithm can be split across small methods without long parameter lists
// and to keep each method's cognitive complexity below Sonar's threshold.
type rectCoalescer struct {
	out                      [][4]int
	prevRowStart, prevRowEnd int
	curRowStart              int
	curY                     int
}

func newRectCoalescer(capacity int) *rectCoalescer {
	return &rectCoalescer{out: make([][4]int, 0, capacity)}
}

// consume processes one rect from the (row-ordered) input.
func (c *rectCoalescer) consume(r [4]int) {
	if r[1] != c.curY {
		c.flushCurrentRow()
		c.prevRowEnd = len(c.out)
		c.curRowStart = len(c.out)
		c.curY = r[1]
	}
	if c.tryHorizontalMerge(r) {
		return
	}
	c.out = append(c.out, r)
}

// tryHorizontalMerge extends the last run in the current row when r is
// vertically aligned and horizontally adjacent to it.
func (c *rectCoalescer) tryHorizontalMerge(r [4]int) bool {
	if len(c.out) <= c.curRowStart {
		return false
	}
	last := &c.out[len(c.out)-1]
	if last[1] == r[1] && last[3] == r[3] && last[0]+last[2] == r[0] {
		last[2] += r[2]
		return true
	}
	return false
}

// flushCurrentRow merges each run in the current row with any run from the
// previous row that has identical x extent and is vertically adjacent.
func (c *rectCoalescer) flushCurrentRow() {
	i := c.curRowStart
	for i < len(c.out) {
		if c.mergeWithPrevRow(i) {
			continue
		}
		i++
	}
}

// mergeWithPrevRow tries to extend a previous-row run downward to absorb
// out[i]. Returns true and removes out[i] from the slice on success.
func (c *rectCoalescer) mergeWithPrevRow(i int) bool {
	for j := c.prevRowStart; j < c.prevRowEnd; j++ {
		if c.out[j][0] == c.out[i][0] &&
			c.out[j][2] == c.out[i][2] &&
			c.out[j][1]+c.out[j][3] == c.out[i][1] {
			c.out[j][3] += c.out[i][3]
			copy(c.out[i:], c.out[i+1:])
			c.out = c.out[:len(c.out)-1]
			return true
		}
	}
	return false
}

func tileChanged(prev, cur *image.RGBA, x, y, w, h int) bool {
	stride := prev.Stride
	for row := y; row < y+h; row++ {
		off := row*stride + x*4
		end := off + w*4
		prevRow := prev.Pix[off:end]
		curRow := cur.Pix[off:end]
		if !bytes.Equal(prevRow, curRow) {
			return true
		}
	}
	return false
}

// tileIsUniform reports whether every pixel in the given rectangle of img is
// the same RGBA value, and returns that pixel packed as 0xRRGGBBAA when so.
// Uses uint32 comparisons across rows; returns early on the first mismatch.
// Returns (0, false) on any out-of-range rectangle so an unsafe pointer
// deref can never reach past img.Pix even if a capturer reports stale
// dimensions or a resize race produces inconsistent state.
func tileIsUniform(img *image.RGBA, x, y, w, h int) (uint32, bool) {
	if w <= 0 || h <= 0 || x < 0 || y < 0 {
		return 0, false
	}
	bounds := img.Rect
	if x+w > bounds.Dx() || y+h > bounds.Dy() {
		return 0, false
	}
	stride := img.Stride
	base := y*stride + x*4
	rowBytes := w * 4
	// Final row's last pixel must be inside Pix; guard against any caller
	// that managed to slip past the bounds check above (e.g. negative
	// stride from a forged image).
	if base < 0 || base+(h-1)*stride+rowBytes > len(img.Pix) {
		return 0, false
	}
	first := *(*uint32)(unsafe.Pointer(&img.Pix[base]))
	for row := 0; row < h; row++ {
		p := base + row*stride
		for col := 0; col < rowBytes; col += 4 {
			if *(*uint32)(unsafe.Pointer(&img.Pix[p+col])) != first {
				return 0, false
			}
		}
	}
	return first, true
}

// tightState holds the per-session JPEG scratch buffer and reused encoders
// so per-rect encoding stays alloc-free in the steady state.
type tightState struct {
	jpegBuf *bytes.Buffer
	zlib    *zlibState
	scratch []byte // RGB-packed pixel scratch for JPEG and Basic paths.
	// colorSeen is reused by sampledColorCount per rect; cleared via the Go
	// runtime's map-clear fast path to avoid a fresh allocation each call.
	colorSeen map[uint32]struct{}
	// jpegQualityOverride forces a fixed JPEG quality on every rect when
	// non-zero (set from the client's QualityLevel pseudo-encoding). Zero
	// falls back to the area-based tiers in tightQualityFor.
	jpegQualityOverride int
	// qualityLevel and compressLevel are the 0..9 levels currently applied,
	// or -1 if the client did not express a preference. Used to decide
	// whether a SetEncodings refresh needs to recreate the tight state.
	qualityLevel  int
	compressLevel int
	// pendingZlibReset becomes true when this tightState replaces an
	// in-use one (e.g. CompressLevel change mid-session). The next Basic
	// rect we emit ORs the stream-0 reset bit into its sub-encoding byte
	// so the client's inflater drops its now-stale dictionary; cleared
	// after one emission.
	pendingZlibReset bool
}

func newTightState() *tightState {
	return newTightStateWithLevels(-1, -1)
}

// newTightStateWithLevels builds a tightState whose zlib stream and JPEG
// quality reflect the client's QualityLevel / CompressLevel pseudo-encodings.
// Pass -1 for either level to keep our defaults (BestSpeed zlib and the
// area-tiered JPEG quality in tightQualityFor).
func newTightStateWithLevels(qualityLevel, compressLevel int) *tightState {
	return &tightState{
		jpegBuf:             &bytes.Buffer{},
		zlib:                newZlibStateLevel(zlibLevelFor(compressLevel)),
		colorSeen:           make(map[uint32]struct{}, 64),
		jpegQualityOverride: jpegQualityForLevel(qualityLevel),
		qualityLevel:        qualityLevel,
		compressLevel:       compressLevel,
	}
}

// jpegQualityForLevel maps a 0..9 client preference to a JPEG quality value.
// Returns 0 when no preference is set (-1), letting the encoder fall back
// to the area-based tiers. The encoder lowers this dynamically when the
// socket is backpressured, so this routine emits the unclamped, client-
// requested value.
func jpegQualityForLevel(level int) int {
	if level < 0 {
		return 0
	}
	if level > 9 {
		level = 9
	}
	return 30 + level*7
}

// zlibLevelFor maps a 0..9 client preference to a zlib compression level.
// Level 0 ("no compression") would emit larger output than input on most
// rects, so we floor to BestSpeed (1). -1 (no preference) also picks
// BestSpeed: matches the historical default before the pseudo-encoding
// was honoured.
func zlibLevelFor(level int) int {
	if level < 1 {
		return zlib.BestSpeed
	}
	if level > zlib.BestCompression {
		return zlib.BestCompression
	}
	return level
}

// tightMaxLength is the maximum payload size representable in the Tight
// compact length prefix (RFB §7.7.6: 22 bits, three 7+7+8 bit groups).
// Exceeding this would silently truncate the high byte; callers must fall
// back to a different encoding when an attempt would overflow.
const tightMaxLength = (1 << 22) - 1

// encodeTightRect emits a single Tight-encoded rect. Picks Fill for uniform
// content, JPEG for photo-like rects above a size and color-count threshold,
// and Basic+zlib otherwise. When Tight's 22-bit length cap would be exceeded
// (huge full-frame rects under bad compression), falls back to Raw. Returns
// the rect header + body (no FramebufferUpdate header).
func encodeTightRect(img *image.RGBA, pf clientPixelFormat, x, y, w, h int, t *tightState) []byte {
	if pixel, uniform := tileIsUniform(img, x, y, w, h); uniform {
		return encodeTightFill(x, y, w, h, byte(pixel), byte(pixel>>8), byte(pixel>>16))
	}
	if w*h >= tightJPEGMinArea && sampledColorCountInto(t.colorSeen, img, x, y, w, h, tightJPEGMinColors) >= tightJPEGMinColors {
		if buf, ok := encodeTightJPEG(img, x, y, w, h, t); ok {
			return buf
		}
	}
	if buf, ok := encodeTightBasic(img, x, y, w, h, t); ok {
		return buf
	}
	// Fall back to Raw rect body (skip the 4-byte FU header that encodeRawRect
	// prepends, since callers compose their own FU header).
	return encodeRawRect(img, pf, x, y, w, h)[4:]
}

func writeTightRectHeader(buf []byte, x, y, w, h int) {
	binary.BigEndian.PutUint16(buf[0:2], uint16(x))
	binary.BigEndian.PutUint16(buf[2:4], uint16(y))
	binary.BigEndian.PutUint16(buf[4:6], uint16(w))
	binary.BigEndian.PutUint16(buf[6:8], uint16(h))
	binary.BigEndian.PutUint32(buf[8:12], uint32(encTight))
}

// appendTightLength encodes a Tight compact length prefix (1, 2, or 3 bytes
// LE-ish, top bit of each byte signals continuation). Lengths exceeding
// tightMaxLength would silently truncate the high byte; callers must clamp
// or fall back before reaching here. Out-of-range values are clamped and
// logged instead of panicking so a malformed encode can't tear the whole
// server down: callers already check the cap, so this branch is just a
// defence-in-depth backstop.
func appendTightLength(buf []byte, n int) []byte {
	if n < 0 {
		log.Warnf("tight length negative (%d); clamping to 0", n)
		n = 0
	}
	if n > tightMaxLength {
		log.Warnf("tight length %d exceeds cap %d; clamping (caller should have fallen back)", n, tightMaxLength)
		n = tightMaxLength
	}
	b0 := byte(n & 0x7f)
	if n <= 0x7f {
		return append(buf, b0)
	}
	b0 |= 0x80
	b1 := byte((n >> 7) & 0x7f)
	if n <= 0x3fff {
		return append(buf, b0, b1)
	}
	b1 |= 0x80
	// High group is 8 bits per spec, but our cap guarantees the top 2 bits
	// are zero; mask defensively.
	b2 := byte((n >> 14) & 0xff)
	return append(buf, b0, b1, b2)
}

// encodeTightFill emits a uniform rect: 12-byte rect header + 1-byte
// subenc (0x80) + 3-byte RGB pixel. Tight Fill always uses 24-bit RGB
// regardless of the negotiated pixel format.
func encodeTightFill(x, y, w, h int, r, g, b byte) []byte {
	buf := make([]byte, 12+1+3)
	writeTightRectHeader(buf, x, y, w, h)
	buf[12] = tightFillSubenc
	buf[13] = r
	buf[14] = g
	buf[15] = b
	return buf
}

// encodeTightJPEG compresses the rect as a baseline JPEG. Returns ok=false
// if the encoder errors so the caller can fall back to Basic.
func encodeTightJPEG(img *image.RGBA, x, y, w, h int, t *tightState) ([]byte, bool) {
	t.jpegBuf.Reset()
	sub := img.SubImage(image.Rect(img.Rect.Min.X+x, img.Rect.Min.Y+y, img.Rect.Min.X+x+w, img.Rect.Min.Y+y+h))
	q := t.jpegQualityOverride
	if q == 0 {
		q = tightQualityFor(w * h)
	}
	if err := jpeg.Encode(t.jpegBuf, sub, &jpeg.Options{Quality: q}); err != nil {
		return nil, false
	}
	jpegBytes := t.jpegBuf.Bytes()
	if len(jpegBytes) > tightMaxLength {
		return nil, false
	}
	buf := make([]byte, 0, 12+1+3+len(jpegBytes))
	buf = buf[:12]
	writeTightRectHeader(buf, x, y, w, h)
	buf = append(buf, tightJPEGSubenc)
	buf = appendTightLength(buf, len(jpegBytes))
	buf = append(buf, jpegBytes...)
	return buf, true
}

// encodeTightBasic emits Basic+zlib with the no-op (CopyFilter) filter.
// Pixels are sent as 24-bit RGB ("TPIXEL" format) which most clients
// negotiate when the server advertises 32bpp true colour. Streams under
// 12 bytes ship uncompressed per RFB Tight spec. Returns ok=false when the
// compressed payload would exceed Tight's 22-bit length cap or when zlib
// errors, signalling the caller to fall back to Raw.
func encodeTightBasic(img *image.RGBA, x, y, w, h int, t *tightState) ([]byte, bool) {
	pixelStream := w * h * 3
	if cap(t.scratch) < pixelStream {
		t.scratch = make([]byte, pixelStream)
	}
	scratch := t.scratch[:pixelStream]
	stride := img.Stride
	off := 0
	for row := y; row < y+h; row++ {
		p := row*stride + x*4
		for col := 0; col < w; col++ {
			scratch[off+0] = img.Pix[p]
			scratch[off+1] = img.Pix[p+1]
			scratch[off+2] = img.Pix[p+2]
			p += 4
			off += 3
		}
	}

	// Sub-encoding byte: stream 0, basic encoding (top nibble = 0x40 =
	// explicit filter follows). The low nibble carries per-stream reset
	// flags; bit 0 here tells the client to reset its stream-0 inflater
	// when our deflater was just recreated.
	subenc := byte(tightBasicFilter)
	if t.pendingZlibReset {
		subenc |= 0x01
		t.pendingZlibReset = false
	}
	filter := byte(tightFilterCopy)

	if pixelStream < 12 {
		buf := make([]byte, 0, 12+2+pixelStream)
		buf = buf[:12]
		writeTightRectHeader(buf, x, y, w, h)
		buf = append(buf, subenc, filter)
		buf = append(buf, scratch...)
		return buf, true
	}

	z := t.zlib
	z.buf.Reset()
	if _, err := z.w.Write(scratch); err != nil {
		log.Debugf("tight zlib write: %v", err)
		return nil, false
	}
	if err := z.w.Flush(); err != nil {
		log.Debugf("tight zlib flush: %v", err)
		return nil, false
	}
	compressed := z.buf.Bytes()
	if len(compressed) > tightMaxLength {
		return nil, false
	}

	buf := make([]byte, 0, 12+2+5+len(compressed))
	buf = buf[:12]
	writeTightRectHeader(buf, x, y, w, h)
	buf = append(buf, subenc, filter)
	buf = appendTightLength(buf, len(compressed))
	buf = append(buf, compressed...)
	return buf, true
}

func tightQualityFor(pixels int) int {
	switch {
	case pixels >= tightJPEGLargePixels:
		return tightJPEGQualityLarge
	case pixels >= tightJPEGMediumPixels:
		return tightJPEGQualityMedium
	default:
		return tightJPEGQuality
	}
}

// sampledColorCountInto estimates distinct-colour count by checking up to
// maxColors samples. The caller-provided `seen` map is cleared and reused so
// per-rect Tight encoding stays alloc-free. Cheap O(maxColors) per call.
func sampledColorCountInto(seen map[uint32]struct{}, img *image.RGBA, x, y, w, h, maxColors int) int {
	clear(seen)
	if w <= 0 || h <= 0 || x < 0 || y < 0 {
		return 0
	}
	bounds := img.Rect
	if x+w > bounds.Dx() || y+h > bounds.Dy() {
		return 0
	}
	stride := img.Stride
	// Defensive: refuse to dereference past the buffer end if stride math
	// somehow disagrees with bounds (e.g. caller passed a SubImage).
	if (y+h-1)*stride+(x+w)*4 > len(img.Pix) {
		return 0
	}
	step := max((w*h)/(maxColors*4), 1)
	var idx int
	for row := 0; row < h; row++ {
		p := (y+row)*stride + x*4
		for col := 0; col < w; col++ {
			if idx%step == 0 {
				px := *(*uint32)(unsafe.Pointer(&img.Pix[p+col*4]))
				seen[px&0x00ffffff] = struct{}{}
				if len(seen) > maxColors {
					return len(seen)
				}
			}
			idx++
		}
	}
	return len(seen)
}

// zlibState holds the persistent zlib writer and its output buffer, reused
// across rects so steady-state Tight encoding stays alloc-free.
type zlibState struct {
	buf *bytes.Buffer
	w   *zlib.Writer
	// scratch stages the packed pixel stream for a rect before it is fed
	// to the deflater. Grown to the largest rect seen in the session and
	// reused to keep the steady-state encode allocation-free.
	scratch []byte
}

func newZlibStateLevel(level int) *zlibState {
	buf := &bytes.Buffer{}
	w, _ := zlib.NewWriterLevel(buf, level)
	return &zlibState{buf: buf, w: w}
}

func (z *zlibState) Close() error {
	return z.w.Close()
}
