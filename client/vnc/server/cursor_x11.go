//go:build (linux && !android) || freebsd

package server

import (
	"fmt"
	"image"
	"sync"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xfixes"
)

// xfixesCursor reports the current X cursor sprite via the XFixes extension.
// CursorSerial changes whenever the server picks a different cursor, so
// callers can cache by serial without comparing pixels.
type xfixesCursor struct {
	mu   sync.Mutex
	conn *xgb.Conn
	// lastPosX/lastPosY hold the cursor screen position observed on the
	// most recent successful GetCursorImage. cursorPositionSource readers
	// share this value so we do not pay a second X round-trip per frame.
	lastPosX, lastPosY int
	hasPos             bool
	// lastImg, lastHotX, lastHotY, lastSerial cache the most recent good
	// GetCursorImage result so transient failures (cursor hidden, server
	// briefly unresponsive) reuse the previous sprite instead of going
	// dark. Without this the encoder's compositing path drops to no-op as
	// soon as the cursor becomes momentarily unavailable.
	lastImg    *image.RGBA
	lastHotX   int
	lastHotY   int
	lastSerial uint64
}

// newXFixesCursor initialises the XFixes extension on conn. Returns an
// error if the extension is unavailable; callers can fall back to no
// cursor emission instead of asking on every frame.
func newXFixesCursor(conn *xgb.Conn) (*xfixesCursor, error) {
	if err := xfixes.Init(conn); err != nil {
		return nil, fmt.Errorf("xfixes init: %w", err)
	}
	if _, err := xfixes.QueryVersion(conn, 4, 0).Reply(); err != nil {
		return nil, fmt.Errorf("xfixes query version: %w", err)
	}
	return &xfixesCursor{conn: conn}, nil
}

// Cursor returns the current cursor sprite as RGBA along with its hotspot
// and serial. Callers should treat an unchanged serial as "no update". On
// a transient GetCursorImage failure the last cached sprite is returned
// so compositing keeps painting the cursor instead of disappearing.
func (c *xfixesCursor) Cursor() (*image.RGBA, int, int, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	reply, err := xfixes.GetCursorImage(c.conn).Reply()
	if err != nil {
		if c.lastImg != nil {
			return c.lastImg, c.lastHotX, c.lastHotY, c.lastSerial, nil
		}
		return nil, 0, 0, 0, fmt.Errorf("xfixes GetCursorImage: %w", err)
	}
	c.lastPosX, c.lastPosY, c.hasPos = int(reply.X), int(reply.Y), true
	w, h := int(reply.Width), int(reply.Height)
	if w <= 0 || h <= 0 {
		if c.lastImg != nil {
			return c.lastImg, c.lastHotX, c.lastHotY, c.lastSerial, nil
		}
		return nil, 0, 0, 0, fmt.Errorf("cursor has zero extent")
	}
	if len(reply.CursorImage) < w*h {
		if c.lastImg != nil {
			return c.lastImg, c.lastHotX, c.lastHotY, c.lastSerial, nil
		}
		return nil, 0, 0, 0, fmt.Errorf("cursor pixel buffer truncated: %d < %d", len(reply.CursorImage), w*h)
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	// XFixes packs each pixel as a uint32 in ARGB order with premultiplied
	// alpha. Unpack into the standard RGBA byte layout.
	for i, p := range reply.CursorImage[:w*h] {
		o := i * 4
		img.Pix[o+0] = byte(p >> 16)
		img.Pix[o+1] = byte(p >> 8)
		img.Pix[o+2] = byte(p)
		img.Pix[o+3] = byte(p >> 24)
	}
	c.lastImg = img
	c.lastHotX = int(reply.Xhot)
	c.lastHotY = int(reply.Yhot)
	c.lastSerial = uint64(reply.CursorSerial)
	return img, c.lastHotX, c.lastHotY, c.lastSerial, nil
}

// Cursor on X11Capturer satisfies cursorSource. The XFixes binding is
// created lazily on the same X connection used for screen capture; the
// first init failure is latched so we stop asking on every frame.
func (x *X11Capturer) Cursor() (*image.RGBA, int, int, uint64, error) {
	x.mu.Lock()
	if x.cursor == nil && x.cursorInitErr == nil {
		x.cursor, x.cursorInitErr = newXFixesCursor(x.conn)
	}
	cur := x.cursor
	initErr := x.cursorInitErr
	x.mu.Unlock()
	if initErr != nil {
		return nil, 0, 0, 0, initErr
	}
	return cur.Cursor()
}

// CursorPos on X11Capturer returns the screen position from the most
// recent successful Cursor() call. Sessions call Cursor() once per encode
// cycle, so this stays current without a second X round-trip.
func (x *X11Capturer) CursorPos() (int, int, error) {
	x.mu.Lock()
	cur := x.cursor
	x.mu.Unlock()
	if cur == nil {
		return 0, 0, fmt.Errorf("cursor source not initialised")
	}
	cur.mu.Lock()
	defer cur.mu.Unlock()
	if !cur.hasPos {
		return 0, 0, fmt.Errorf("cursor position not sampled yet")
	}
	return cur.lastPosX, cur.lastPosY, nil
}
