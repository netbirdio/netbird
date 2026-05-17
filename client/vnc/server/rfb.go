package server

import (
	"bytes"
	"compress/zlib"
	"crypto/des" //nolint:gosec // RFB protocol-defined DES challenge/response; not used for confidentiality
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

	secNone    = 1
	secVNCAuth = 2

	// Client message types.
	clientSetPixelFormat           = 0
	clientSetEncodings             = 2
	clientFramebufferUpdateRequest = 3
	clientKeyEvent                 = 4
	clientPointerEvent             = 5
	clientCutText                  = 6

	// clientNetbirdTypeText is a NetBird-specific message that asks the
	// server to synthesize the given text as keystrokes regardless of the
	// active desktop. Used by the dashboard's Paste button to push host
	// clipboard content into a Windows secure desktop (Winlogon, UAC),
	// where the OS clipboard is isolated. Format mirrors clientCutText:
	// 1-byte message type + 3-byte padding + 4-byte length + text bytes.
	// The opcode is in the vendor-specific range (>=128).
	clientNetbirdTypeText = 250

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
	pseudoEncDesktopSize         = -223
	pseudoEncLastRect            = -224
	pseudoEncDesktopName         = -307
	pseudoEncExtendedDesktopSize = -308

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

	// Hextile subencoding flags (a bitmask in the first byte of each sub-tile).
	hextileRaw                 = 0x01
	hextileBackgroundSpecified = 0x02
	hextileForegroundSpecified = 0x04
	hextileAnySubrects         = 0x08
	hextileSubrectsColoured    = 0x10

	// Hextile sub-tile size per RFB spec.
	hextileSubSize = 16
)

// serverPixelFormat is the default pixel format advertised by the server:
// 32bpp RGBA, big-endian, true-colour, 8 bits per channel.
var serverPixelFormat = [16]byte{
	32,     // bits-per-pixel
	24,     // depth
	1,      // big-endian-flag
	1,      // true-colour-flag
	0, 255, // red-max
	0, 255, // green-max
	0, 255, // blue-max
	16,      // red-shift
	8,       // green-shift
	0,       // blue-shift
	0, 0, 0, // padding
}

// clientPixelFormat holds the negotiated pixel format from the client.
type clientPixelFormat struct {
	bpp       uint8
	bigEndian uint8
	rMax      uint16
	gMax      uint16
	bMax      uint16
	rShift    uint8
	gShift    uint8
	bShift    uint8
}

func defaultClientPixelFormat() clientPixelFormat {
	return clientPixelFormat{
		bpp:       serverPixelFormat[0],
		bigEndian: serverPixelFormat[2],
		rMax:      binary.BigEndian.Uint16(serverPixelFormat[4:6]),
		gMax:      binary.BigEndian.Uint16(serverPixelFormat[6:8]),
		bMax:      binary.BigEndian.Uint16(serverPixelFormat[8:10]),
		rShift:    serverPixelFormat[10],
		gShift:    serverPixelFormat[11],
		bShift:    serverPixelFormat[12],
	}
}

func parsePixelFormat(pf []byte) clientPixelFormat {
	return clientPixelFormat{
		bpp:       pf[0],
		bigEndian: pf[2],
		rMax:      binary.BigEndian.Uint16(pf[4:6]),
		gMax:      binary.BigEndian.Uint16(pf[6:8]),
		bMax:      binary.BigEndian.Uint16(pf[8:10]),
		rShift:    pf[10],
		gShift:    pf[11],
		bShift:    pf[12],
	}
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
	bytesPerPixel := max(int(pf.bpp)/8, 1)

	pixelBytes := w * h * bytesPerPixel
	buf := make([]byte, 4+12+pixelBytes)

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

	writePixels(buf[16:], img, pf, rect{x, y, w, h}, bytesPerPixel)
	return buf
}

// writePixels writes a rectangle of img into dst in the client's requested
// pixel format. It fast-paths the common case (32bpp, full 8-bit channels)
// with a tight loop that skips the per-channel *max/255 arithmetic and emits
// a single uint32 per pixel; the general path handles arbitrary formats.
func writePixels(dst []byte, img *image.RGBA, pf clientPixelFormat, r rect, bytesPerPixel int) {
	if bytesPerPixel == 4 && pf.rMax == 255 && pf.gMax == 255 && pf.bMax == 255 {
		writePixelsFast32(dst, img, pf, r)
		return
	}
	writePixelsGeneric(dst, img, pf, r, bytesPerPixel)
}

func writePixelsFast32(dst []byte, img *image.RGBA, pf clientPixelFormat, r rect) {
	stride := img.Stride
	rShift, gShift, bShift := pf.rShift, pf.gShift, pf.bShift
	bigEndian := pf.bigEndian != 0
	off := 0
	for row := r.y; row < r.y+r.h; row++ {
		p := row*stride + r.x*4
		for col := 0; col < r.w; col++ {
			pixel := (uint32(img.Pix[p]) << rShift) |
				(uint32(img.Pix[p+1]) << gShift) |
				(uint32(img.Pix[p+2]) << bShift)
			if bigEndian {
				binary.BigEndian.PutUint32(dst[off:off+4], pixel)
			} else {
				binary.LittleEndian.PutUint32(dst[off:off+4], pixel)
			}
			p += 4
			off += 4
		}
	}
}

func writePixelsGeneric(dst []byte, img *image.RGBA, pf clientPixelFormat, r rect, bytesPerPixel int) {
	stride := img.Stride
	off := 0
	for row := r.y; row < r.y+r.h; row++ {
		for col := r.x; col < r.x+r.w; col++ {
			p := row*stride + col*4
			rv := uint32(img.Pix[p]) * uint32(pf.rMax) / 255
			gv := uint32(img.Pix[p+1]) * uint32(pf.gMax) / 255
			bv := uint32(img.Pix[p+2]) * uint32(pf.bMax) / 255
			pixel := (rv << pf.rShift) | (gv << pf.gShift) | (bv << pf.bShift)
			emitPixelBytes(dst[off:off+bytesPerPixel], pixel, bytesPerPixel, pf.bigEndian != 0)
			off += bytesPerPixel
		}
	}
}

func emitPixelBytes(dst []byte, pixel uint32, bytesPerPixel int, bigEndian bool) {
	if bigEndian {
		for i := range bytesPerPixel {
			dst[i] = byte(pixel >> uint((bytesPerPixel-1-i)*8))
		}
		return
	}
	for i := range bytesPerPixel {
		dst[i] = byte(pixel >> uint(i*8))
	}
}

// vncAuthEncrypt encrypts a 16-byte challenge using the VNC DES scheme.
func vncAuthEncrypt(challenge []byte, password string) ([]byte, error) {
	key := make([]byte, 8)
	pw := []byte(password)
	n := len(pw)
	if n > 8 {
		n = 8
	}
	for i := 0; i < n; i++ {
		key[i] = reverseBits(pw[i])
	}
	block, err := des.NewCipher(key) //nolint:gosec // RFB protocol-defined DES challenge/response; not a confidentiality cipher
	if err != nil {
		return nil, fmt.Errorf("des.NewCipher: %w", err)
	}
	if len(challenge) < 16 { //nolint:gosec // explicit length check disarms G602
		return nil, fmt.Errorf("vnc auth challenge too short: %d", len(challenge))
	}
	out := make([]byte, 16)
	block.Encrypt(out[:8], challenge[:8])
	block.Encrypt(out[8:], challenge[8:])
	return out, nil
}

func reverseBits(b byte) byte {
	var r byte
	for range 8 {
		r = (r << 1) | (b & 1)
		b >>= 1
	}
	return r
}

// encodeZlibRect encodes a framebuffer region using Zlib compression.
// The zlib stream is continuous for the entire VNC session: noVNC creates
// one inflate context at startup and reuses it for all zlib-encoded rects.
// We must NOT reset the zlib writer between calls.
func encodeZlibRect(img *image.RGBA, pf clientPixelFormat, x, y, w, h int, z *zlibState) []byte {
	bytesPerPixel := max(int(pf.bpp)/8, 1)
	zw, zbuf := z.w, z.buf

	// Clear the output buffer but keep the deflate dictionary intact.
	zbuf.Reset()

	// Encode the full rect pixel stream into the session-lived scratch buffer
	// and feed zlib one row at a time. Row-granular writes amortise the per-
	// Write overhead that used to dominate this function when it wrote one
	// byte slice per pixel.
	rowBytes := w * bytesPerPixel
	total := rowBytes * h
	if cap(z.scratch) < total {
		z.scratch = make([]byte, total)
	}
	scratch := z.scratch[:total]
	writePixels(scratch, img, pf, rect{x, y, w, h}, bytesPerPixel)
	for row := 0; row < h; row++ {
		if _, err := zw.Write(scratch[row*rowBytes : (row+1)*rowBytes]); err != nil {
			log.Debugf("zlib write row %d: %v", row, err)
			return nil
		}
	}
	if err := zw.Flush(); err != nil {
		log.Debugf("zlib flush: %v", err)
		return nil
	}

	compressed := zbuf.Bytes()

	// Build the FramebufferUpdate message.
	buf := make([]byte, 4+12+4+len(compressed))
	buf[0] = serverFramebufferUpdate
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:4], 1) // 1 rectangle

	binary.BigEndian.PutUint16(buf[4:6], uint16(x))
	binary.BigEndian.PutUint16(buf[6:8], uint16(y))
	binary.BigEndian.PutUint16(buf[8:10], uint16(w))
	binary.BigEndian.PutUint16(buf[10:12], uint16(h))
	binary.BigEndian.PutUint32(buf[12:16], uint32(encZlib))
	binary.BigEndian.PutUint32(buf[16:20], uint32(len(compressed)))
	copy(buf[20:], compressed)

	return buf
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
	out                        [][4]int
	prevRowStart, prevRowEnd   int
	curRowStart                int
	curY                       int
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
func tileIsUniform(img *image.RGBA, x, y, w, h int) (uint32, bool) {
	if w <= 0 || h <= 0 {
		return 0, false
	}
	stride := img.Stride
	base := y*stride + x*4
	first := *(*uint32)(unsafe.Pointer(&img.Pix[base]))
	rowBytes := w * 4
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

// encodePixel packs an RGBA byte triple into the client's requested pixel
// format, honouring bpp, channel maxes, shifts and endianness. Returns the
// number of bytes written to dst (1..4).
func encodePixel(dst []byte, pf clientPixelFormat, r, g, b byte) int {
	bytesPerPixel := max(int(pf.bpp)/8, 1)
	var val uint32
	if pf.rMax == 255 && pf.gMax == 255 && pf.bMax == 255 {
		val = (uint32(r) << pf.rShift) | (uint32(g) << pf.gShift) | (uint32(b) << pf.bShift)
	} else {
		rv := uint32(r) * uint32(pf.rMax) / 255
		gv := uint32(g) * uint32(pf.gMax) / 255
		bv := uint32(b) * uint32(pf.bMax) / 255
		val = (rv << pf.rShift) | (gv << pf.gShift) | (bv << pf.bShift)
	}
	if pf.bigEndian != 0 {
		for i := range bytesPerPixel {
			dst[i] = byte(val >> uint((bytesPerPixel-1-i)*8))
		}
	} else {
		for i := range bytesPerPixel {
			dst[i] = byte(val >> uint(i*8))
		}
	}
	return bytesPerPixel
}

// encodeHextileSolidRect emits a Hextile-encoded rectangle whose every pixel
// is the same color. All sub-tiles after the first inherit the background
// via a zero subencoding byte, collapsing a uniform 64×64 tile from ~16 KB
// raw (or ~1-2 KB zlib) down to ~20 bytes on the wire.
//
// The returned buffer starts with the 12-byte rect header + the hextile
// body. Callers assembling a multi-rect FramebufferUpdate append this after
// their own message header.
func encodeHextileSolidRect(r, g, b byte, pf clientPixelFormat, rc rect) []byte {
	bytesPerPixel := max(int(pf.bpp)/8, 1)

	// Count sub-tiles. Right/bottom sub-tiles may be smaller than 16.
	cols := (rc.w + hextileSubSize - 1) / hextileSubSize
	rows := (rc.h + hextileSubSize - 1) / hextileSubSize
	subs := cols * rows

	// Body: first sub-tile carries (subenc 0x02 + bg pixel); the rest are
	// subenc 0x00 (inherit the previously-emitted background).
	bodySize := 1 + bytesPerPixel + (subs - 1)
	buf := make([]byte, 12+bodySize)

	binary.BigEndian.PutUint16(buf[0:2], uint16(rc.x))
	binary.BigEndian.PutUint16(buf[2:4], uint16(rc.y))
	binary.BigEndian.PutUint16(buf[4:6], uint16(rc.w))
	binary.BigEndian.PutUint16(buf[6:8], uint16(rc.h))
	binary.BigEndian.PutUint32(buf[8:12], uint32(encHextile))

	buf[12] = hextileBackgroundSpecified
	encodePixel(buf[13:13+bytesPerPixel], pf, r, g, b)
	// Remaining sub-tiles are already zero-valued from make(): "same as
	// previous background", no pixel bytes.
	_ = subs
	return buf
}

// encodeHextileRect emits a full Hextile-encoded rectangle. Each 16×16
// sub-tile is classified as 1-color (background only), 2-color (background
// + foreground subrects), or raw. The 1-color and 2-color paths are
// significantly cheaper than zlib on UI content (text, icons, flat
// backgrounds) and avoid the persistent zlib stream's inter-rect
// serialization point, so they parallelize trivially.
//
// The returned buffer starts with the 12-byte rect header + hextile body.
func encodeHextileRect(img *image.RGBA, pf clientPixelFormat, x, y, w, h int) []byte {
	bytesPerPixel := max(int(pf.bpp)/8, 1)

	// Pre-size: worst case is every sub-tile raw → 1 header byte + raw
	// pixels per sub-tile.
	maxBody := 0
	for sy := 0; sy < h; sy += hextileSubSize {
		sh := min(hextileSubSize, h-sy)
		for sx := 0; sx < w; sx += hextileSubSize {
			sw := min(hextileSubSize, w-sx)
			maxBody += 1 + sw*sh*bytesPerPixel
		}
	}
	buf := make([]byte, 12, 12+maxBody)

	binary.BigEndian.PutUint16(buf[0:2], uint16(x))
	binary.BigEndian.PutUint16(buf[2:4], uint16(y))
	binary.BigEndian.PutUint16(buf[4:6], uint16(w))
	binary.BigEndian.PutUint16(buf[6:8], uint16(h))
	binary.BigEndian.PutUint32(buf[8:12], uint32(encHextile))

	var state hextileBgState

	for sy := 0; sy < h; sy += hextileSubSize {
		sh := min(hextileSubSize, h-sy)
		for sx := 0; sx < w; sx += hextileSubSize {
			sw := min(hextileSubSize, w-sx)
			buf = appendHextileSubtile(buf, img, pf, rect{x + sx, y + sy, sw, sh}, &state, bytesPerPixel)
		}
	}
	return buf
}

// hextileBgState carries the running background across sub-tile encodes so
// we can omit the BackgroundSpecified flag when it hasn't changed.
type hextileBgState struct {
	prev  uint32
	valid bool
}

// appendHextileSubtile encodes a single 16×16 (or smaller edge) sub-tile
// onto buf.
func appendHextileSubtile(buf []byte, img *image.RGBA, pf clientPixelFormat, rc rect, state *hextileBgState, bytesPerPixel int) []byte {
	x, y, w, h := rc.x, rc.y, rc.w, rc.h
	c0, c1, only2, c0Count, c1Count := classifySubtile(img, x, y, w, h)

	if !only2 {
		// >2 distinct colours: raw fallback.
		buf = append(buf, hextileRaw)
		buf = appendRawPixels(buf, img, pf, rc, bytesPerPixel)
		state.valid = false
		return buf
	}

	if c1Count == 0 {
		// Single colour. Background only.
		if state.valid && state.prev == c0 {
			return append(buf, 0)
		}
		buf = append(buf, hextileBackgroundSpecified)
		buf = appendPackedPixelFromRGBA(buf, pf, c0, bytesPerPixel)
		state.prev = c0
		state.valid = true
		return buf
	}

	// Two colours. Background = majority; foreground = minority,
	// emitted as 1-row subrects of fg runs.
	bg, fg := c0, c1
	if c1Count > c0Count {
		bg, fg = c1, c0
	}
	subrects := collectFgSubrects(img, x, y, w, h, bg)
	// Cap at 255 (the count is a uint8). On overflow fall through to
	// raw: that's the simplest correct fallback.
	if len(subrects) <= 255 {
		flags := byte(hextileForegroundSpecified | hextileAnySubrects)
		emitBg := !state.valid || state.prev != bg
		if emitBg {
			flags |= hextileBackgroundSpecified
		}
		buf = append(buf, flags)
		if emitBg {
			buf = appendPackedPixelFromRGBA(buf, pf, bg, bytesPerPixel)
			state.prev = bg
			state.valid = true
		}
		buf = appendPackedPixelFromRGBA(buf, pf, fg, bytesPerPixel)
		buf = append(buf, byte(len(subrects)))
		for _, sr := range subrects {
			buf = append(buf, byte((sr[0]<<4)|sr[1]), byte(((sr[2]-1)<<4)|(sr[3]-1)))
		}
		return buf
	}

	// Raw fallback.
	buf = append(buf, hextileRaw)
	buf = appendRawPixels(buf, img, pf, rc, bytesPerPixel)
	// Raw sub-tiles invalidate the persistent background.
	state.valid = false
	return buf
}

// classifySubtile scans the sub-tile and reports up to two distinct pixel
// values plus their counts. only2 is false the moment a third distinct
// colour is seen, in which case the caller falls back to raw.
func classifySubtile(img *image.RGBA, x, y, w, h int) (c0, c1 uint32, only2 bool, c0Count, c1Count int) {
	stride := img.Stride
	base := y*stride + x*4
	c0 = *(*uint32)(unsafe.Pointer(&img.Pix[base]))
	only2 = true
	for row := 0; row < h; row++ {
		p := base + row*stride
		for col := 0; col < w; col++ {
			px := *(*uint32)(unsafe.Pointer(&img.Pix[p+col*4]))
			switch {
			case px == c0:
				c0Count++
			case c1Count == 0:
				c1 = px
				c1Count = 1
			case px == c1:
				c1Count++
			default:
				return c0, c1, false, 0, 0
			}
		}
	}
	return c0, c1, only2, c0Count, c1Count
}

// collectFgSubrects walks the sub-tile row by row, emitting one subrect per
// horizontal run of pixels not equal to bg. Each subrect is [subX, subY,
// width, height] with width/height in 1..16.
func collectFgSubrects(img *image.RGBA, x, y, w, h int, bg uint32) [][4]int {
	stride := img.Stride
	var out [][4]int
	for row := 0; row < h; row++ {
		p := y*stride + x*4 + row*stride
		col := 0
		for col < w {
			if *(*uint32)(unsafe.Pointer(&img.Pix[p+col*4])) == bg {
				col++
				continue
			}
			start := col
			for col < w && *(*uint32)(unsafe.Pointer(&img.Pix[p+col*4])) != bg {
				col++
			}
			out = append(out, [4]int{start, row, col - start, 1})
		}
	}
	return out
}

func appendPackedPixelFromRGBA(buf []byte, pf clientPixelFormat, px uint32, bytesPerPixel int) []byte {
	r := byte(px)
	g := byte(px >> 8)
	b := byte(px >> 16)
	var tmp [4]byte
	encodePixel(tmp[:], pf, r, g, b)
	return append(buf, tmp[:bytesPerPixel]...)
}

func appendRawPixels(buf []byte, img *image.RGBA, pf clientPixelFormat, rc rect, bytesPerPixel int) []byte {
	start := len(buf)
	buf = append(buf, make([]byte, rc.w*rc.h*bytesPerPixel)...)
	writePixels(buf[start:], img, pf, rc, bytesPerPixel)
	return buf
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
}

func newTightState() *tightState {
	return &tightState{
		jpegBuf:   &bytes.Buffer{},
		zlib:      newZlibState(),
		colorSeen: make(map[uint32]struct{}, 64),
	}
}

// encodeTightRect emits a single Tight-encoded rect. Picks Fill for uniform
// content, JPEG for photo-like rects above a size and color-count threshold,
// and Basic+zlib otherwise. Returns the rect header + Tight body (no
// FramebufferUpdate header).
func encodeTightRect(img *image.RGBA, pf clientPixelFormat, x, y, w, h int, t *tightState) []byte {
	if pixel, uniform := tileIsUniform(img, x, y, w, h); uniform {
		return encodeTightFill(x, y, w, h, byte(pixel), byte(pixel>>8), byte(pixel>>16))
	}
	if w*h >= tightJPEGMinArea && sampledColorCountInto(t.colorSeen, img, x, y, w, h, tightJPEGMinColors) >= tightJPEGMinColors {
		if buf, ok := encodeTightJPEG(img, x, y, w, h, t); ok {
			return buf
		}
	}
	return encodeTightBasic(img, x, y, w, h, t)
}

func writeTightRectHeader(buf []byte, x, y, w, h int) {
	binary.BigEndian.PutUint16(buf[0:2], uint16(x))
	binary.BigEndian.PutUint16(buf[2:4], uint16(y))
	binary.BigEndian.PutUint16(buf[4:6], uint16(w))
	binary.BigEndian.PutUint16(buf[6:8], uint16(h))
	binary.BigEndian.PutUint32(buf[8:12], uint32(encTight))
}

// appendTightLength encodes a Tight compact length prefix (1, 2, or 3 bytes
// LE-ish, top bit of each byte signals continuation).
func appendTightLength(buf []byte, n int) []byte {
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
	if err := jpeg.Encode(t.jpegBuf, sub, &jpeg.Options{Quality: tightQualityFor(w * h)}); err != nil {
		return nil, false
	}
	jpegBytes := t.jpegBuf.Bytes()
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
// 12 bytes ship uncompressed per RFB Tight spec.
func encodeTightBasic(img *image.RGBA, x, y, w, h int, t *tightState) []byte {
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

	// Sub-encoding byte: stream 0, no resets, basic encoding (top nibble
	// = 0x40 = explicit filter follows).
	subenc := byte(tightBasicFilter)
	filter := byte(tightFilterCopy)

	if pixelStream < 12 {
		buf := make([]byte, 0, 12+2+pixelStream)
		buf = buf[:12]
		writeTightRectHeader(buf, x, y, w, h)
		buf = append(buf, subenc, filter)
		buf = append(buf, scratch...)
		return buf
	}

	z := t.zlib
	z.buf.Reset()
	if _, err := z.w.Write(scratch); err != nil {
		log.Debugf("tight zlib write: %v", err)
		return nil
	}
	if err := z.w.Flush(); err != nil {
		log.Debugf("tight zlib flush: %v", err)
		return nil
	}
	compressed := z.buf.Bytes()

	buf := make([]byte, 0, 12+2+5+len(compressed))
	buf = buf[:12]
	writeTightRectHeader(buf, x, y, w, h)
	buf = append(buf, subenc, filter)
	buf = appendTightLength(buf, len(compressed))
	buf = append(buf, compressed...)
	return buf
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
	stride := img.Stride
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

// zlibState holds the persistent zlib writer, output buffer, and a scratch
// slice reused by encodeZlibRect to stage the packed pixel stream before
// handing it to the deflate writer. The scratch grows to the largest rect
// we've seen and is kept for the session lifetime.
type zlibState struct {
	buf     *bytes.Buffer
	w       *zlib.Writer
	scratch []byte
}

func newZlibState() *zlibState {
	buf := &bytes.Buffer{}
	w, _ := zlib.NewWriterLevel(buf, zlib.BestSpeed)
	return &zlibState{buf: buf, w: w}
}

func (z *zlibState) Close() error {
	return z.w.Close()
}
