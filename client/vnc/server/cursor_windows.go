//go:build windows

package server

import (
	"fmt"
	"image"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procGetCursorInfo = user32.NewProc("GetCursorInfo")
	procGetIconInfo   = user32.NewProc("GetIconInfo")
	procGetObjectW    = gdi32.NewProc("GetObjectW")
	procGetDIBits     = gdi32.NewProc("GetDIBits")
)

const (
	cursorShowing   = 0x00000001
	diRgbColors     = 0
	biRgb           = 0
	dibSectionBytes = 40 // sizeof(BITMAPINFOHEADER)
)

// hiddenHandle is a sentinel stored in cursorSampler.lastHandle while
// Windows reports the cursor as hidden. It is not a valid HCURSOR value;
// real handles never collide with this constant.
const hiddenHandle = windows.Handle(^uintptr(0))

// transparentCursorImage returns a 1x1 fully transparent sprite. The
// client renders this as "no cursor"; emitting it explicitly lets us
// recover when an app un-hides the cursor a moment later.
func transparentCursorImage() *image.RGBA {
	return image.NewRGBA(image.Rect(0, 0, 1, 1))
}

type winPoint struct {
	X, Y int32
}

type winCursorInfo struct {
	Size   uint32
	Flags  uint32
	Cursor windows.Handle
	PtPos  winPoint
}

type winIconInfo struct {
	FIcon    int32
	XHotspot uint32
	YHotspot uint32
	HbmMask  windows.Handle
	HbmColor windows.Handle
}

type winBitmap struct {
	BmType       int32
	BmWidth      int32
	BmHeight     int32
	BmWidthBytes int32
	BmPlanes     uint16
	BmBitsPixel  uint16
	BmBits       uintptr
}

type winBitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

// cursorSnapshot is the captured cursor state shared between the worker
// (which polls the OS) and the session encoder (which reads it).
type cursorSnapshot struct {
	img    *image.RGBA
	hotX   int
	hotY   int
	posX   int
	posY   int
	hasPos bool
	serial uint64
	err    error
}

// cursorSampler captures the foreground process's cursor sprite via Win32
// APIs. It must be called from a goroutine attached to the same window
// station and desktop as the user session (the capture worker does this
// via switchToInputDesktop). lastHandle dedupes per-shape work so we only
// touch GDI when Windows hands us a new cursor.
type cursorSampler struct {
	lastHandle windows.Handle
	serial     uint64
	snapshot   *cursorSnapshot
}

// sample queries the current cursor and decodes a new sprite when Windows
// reports a different HCURSOR than last time. Returns the current snapshot
// regardless of whether anything changed; callers diff by serial.
func (s *cursorSampler) sample() (*cursorSnapshot, error) {
	var ci winCursorInfo
	ci.Size = uint32(unsafe.Sizeof(ci))
	r, _, err := procGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci)))
	if r == 0 {
		return nil, fmt.Errorf("GetCursorInfo: %w", err)
	}
	if ci.Flags&cursorShowing == 0 || ci.Cursor == 0 {
		// Cursor temporarily hidden by an app (text fields toggle it on
		// focus). Emit a 1x1 transparent sprite so the client renders no
		// cursor and stay armed for the next handle change rather than
		// treating this as a hard failure that would latch us off for
		// the session.
		if s.lastHandle == hiddenHandle {
			s.snapshot.posX = int(ci.PtPos.X)
			s.snapshot.posY = int(ci.PtPos.Y)
			s.snapshot.hasPos = true
			return s.snapshot, nil
		}
		s.lastHandle = hiddenHandle
		s.serial++
		s.snapshot = &cursorSnapshot{
			img:    transparentCursorImage(),
			posX:   int(ci.PtPos.X),
			posY:   int(ci.PtPos.Y),
			hasPos: true,
			serial: s.serial,
		}
		return s.snapshot, nil
	}
	if ci.Cursor == s.lastHandle && s.snapshot != nil {
		s.snapshot.posX = int(ci.PtPos.X)
		s.snapshot.posY = int(ci.PtPos.Y)
		s.snapshot.hasPos = true
		return s.snapshot, nil
	}
	img, hotX, hotY, err := decodeCursor(ci.Cursor)
	if err != nil {
		return nil, err
	}
	s.lastHandle = ci.Cursor
	s.serial++
	s.snapshot = &cursorSnapshot{
		img:    img,
		hotX:   hotX,
		hotY:   hotY,
		posX:   int(ci.PtPos.X),
		posY:   int(ci.PtPos.Y),
		hasPos: true,
		serial: s.serial,
	}
	return s.snapshot, nil
}

// decodeCursor extracts the sprite at hCur as RGBA along with the hotspot.
// Color cursors are read from the colour bitmap with the AND mask combined
// in for alpha. Monochrome cursors collapse the two halves of the mask
// bitmap into a single visible sprite where the AND bit drives alpha.
func decodeCursor(hCur windows.Handle) (*image.RGBA, int, int, error) {
	var info winIconInfo
	r, _, err := procGetIconInfo.Call(uintptr(hCur), uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return nil, 0, 0, fmt.Errorf("GetIconInfo: %w", err)
	}
	defer func() {
		if info.HbmMask != 0 {
			_, _, _ = procDeleteObject.Call(uintptr(info.HbmMask))
		}
		if info.HbmColor != 0 {
			_, _, _ = procDeleteObject.Call(uintptr(info.HbmColor))
		}
	}()
	hotX, hotY := int(info.XHotspot), int(info.YHotspot)
	if info.HbmColor != 0 {
		img, err := decodeColorCursor(info.HbmColor, info.HbmMask)
		if err != nil {
			return nil, 0, 0, err
		}
		return img, hotX, hotY, nil
	}
	img, err := decodeMonoCursor(info.HbmMask)
	if err != nil {
		return nil, 0, 0, err
	}
	return img, hotX, hotY, nil
}

// readBitmap returns the BITMAP descriptor for hbm.
func readBitmap(hbm windows.Handle) (winBitmap, error) {
	var bm winBitmap
	r, _, err := procGetObjectW.Call(uintptr(hbm), unsafe.Sizeof(bm), uintptr(unsafe.Pointer(&bm)))
	if r == 0 {
		return winBitmap{}, fmt.Errorf("GetObject: %w", err)
	}
	return bm, nil
}

// dibCopy reads hbm as 32bpp top-down BGRA into a freshly allocated slice
// matching w*h*4 bytes. The bitmap may be selected into the screen DC so
// we use a memory DC to keep the call cheap.
func dibCopy(hbm windows.Handle, w, h int32) ([]byte, error) {
	hdcScreen, _, _ := procGetDC.Call(0)
	if hdcScreen == 0 {
		return nil, fmt.Errorf("GetDC: failed")
	}
	defer func() { _, _, _ = procReleaseDC.Call(0, hdcScreen) }()
	hdcMem, _, _ := procCreateCompatDC.Call(hdcScreen)
	if hdcMem == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC: failed")
	}
	defer func() { _, _, _ = procDeleteDC.Call(hdcMem) }()

	var bih winBitmapInfoHeader
	bih.BiSize = dibSectionBytes
	bih.BiWidth = w
	bih.BiHeight = -h // top-down
	bih.BiPlanes = 1
	bih.BiBitCount = 32
	bih.BiCompression = biRgb

	if w <= 0 || h <= 0 || w > maxCursorDim || h > maxCursorDim {
		return nil, fmt.Errorf("dibCopy: cursor dims %dx%d out of range (max %d)", w, h, maxCursorDim)
	}
	buf := make([]byte, int(w)*int(h)*4)
	r, _, err := procGetDIBits.Call(
		hdcMem,
		uintptr(hbm),
		0,
		uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bih)),
		diRgbColors,
	)
	if r == 0 {
		return nil, fmt.Errorf("GetDIBits: %w", err)
	}
	return buf, nil
}

// decodeColorCursor reads a 32bpp colour cursor and folds the AND mask into
// the alpha channel when the colour bitmap leaves it zero.
func decodeColorCursor(hbmColor, hbmMask windows.Handle) (*image.RGBA, error) {
	bm, err := readBitmap(hbmColor)
	if err != nil {
		return nil, err
	}
	w, h := bm.BmWidth, bm.BmHeight
	color, err := dibCopy(hbmColor, w, h)
	if err != nil {
		return nil, err
	}
	var mask []byte
	if hbmMask != 0 {
		mask, _ = dibCopy(hbmMask, w, h)
	}
	hasAlpha := colorHasAlpha(color)
	img := image.NewRGBA(image.Rect(0, 0, int(w), int(h)))
	for y := int32(0); y < h; y++ {
		for x := int32(0); x < w; x++ {
			si := (y*w + x) * 4
			b := color[si]
			g := color[si+1]
			r := color[si+2]
			a := pixelAlpha(color[si+3], si, mask, hasAlpha)
			// Premultiply so the shared compositor can use the same
			// formula on every platform (X11 XFixes and macOS CG return
			// premultiplied bytes natively).
			if a != 255 && a != 0 {
				r = byte(uint32(r) * uint32(a) / 255)
				g = byte(uint32(g) * uint32(a) / 255)
				b = byte(uint32(b) * uint32(a) / 255)
			} else if a == 0 {
				r, g, b = 0, 0, 0
			}
			img.Pix[si+0] = r
			img.Pix[si+1] = g
			img.Pix[si+2] = b
			img.Pix[si+3] = a
		}
	}
	return img, nil
}

// colorHasAlpha reports whether any pixel of a 32bpp BGRA buffer has a
// non-zero alpha. Cursors authored without alpha leave the channel at 0
// and rely on hbmMask for transparency.
func colorHasAlpha(color []byte) bool {
	for i := 0; i < len(color); i += 4 {
		if color[i+3] != 0 {
			return true
		}
	}
	return false
}

// pixelAlpha returns the effective alpha for a colour-cursor pixel. When
// the source bitmap already has alpha we trust it; otherwise the AND mask
// decides (1 = transparent, 0 = opaque). The 32bpp DIB stores each AND
// bit as a 4-byte entry; the first byte carries the effective value.
func pixelAlpha(colorA byte, si int32, mask []byte, hasAlpha bool) byte {
	if hasAlpha {
		return colorA
	}
	if mask != nil && mask[si] != 0 {
		return 0
	}
	return 255
}

// decodeMonoCursor handles legacy 1bpp cursors where hbmMask is twice as
// tall as the visible sprite: rows [0..h) are the AND mask and rows [h..2h)
// are the XOR mask. We render the visible half into RGBA, treating
// AND-mask=1 as transparent and the XOR bit as a black/white pixel.
func decodeMonoCursor(hbmMask windows.Handle) (*image.RGBA, error) {
	bm, err := readBitmap(hbmMask)
	if err != nil {
		return nil, err
	}
	w, fullH := bm.BmWidth, bm.BmHeight
	if fullH%2 != 0 {
		return nil, fmt.Errorf("unexpected mono cursor shape: %dx%d", w, fullH)
	}
	h := fullH / 2
	data, err := dibCopy(hbmMask, w, fullH)
	if err != nil {
		return nil, err
	}
	img := image.NewRGBA(image.Rect(0, 0, int(w), int(h)))
	for y := int32(0); y < h; y++ {
		for x := int32(0); x < w; x++ {
			and := data[(y*w+x)*4]
			xor := data[((y+h)*w+x)*4]
			di := (y*w + x) * 4
			if and != 0 {
				img.Pix[di+3] = 0
				continue
			}
			c := byte(0)
			if xor != 0 {
				c = 255
			}
			img.Pix[di+0] = c
			img.Pix[di+1] = c
			img.Pix[di+2] = c
			img.Pix[di+3] = 255
		}
	}
	return img, nil
}

// cursorState is the latest snapshot shared between the worker and
// session readers.
type cursorState struct {
	mu       sync.Mutex
	snapshot *cursorSnapshot
}

func (s *cursorState) store(snap *cursorSnapshot) {
	s.mu.Lock()
	s.snapshot = snap
	s.mu.Unlock()
}

func (s *cursorState) load() *cursorSnapshot {
	s.mu.Lock()
	snap := s.snapshot
	s.mu.Unlock()
	return snap
}

// Cursor satisfies cursorSource by returning the latest snapshot the
// capture worker decoded. The "no sample yet" and "cursor hidden" cases
// return img=nil with no error so callers skip emission this cycle
// without latching the source off for the rest of the session.
func (c *DesktopCapturer) Cursor() (*image.RGBA, int, int, uint64, error) {
	snap := c.cursorState.load()
	if snap == nil {
		return nil, 0, 0, 0, nil
	}
	if snap.err != nil {
		return nil, 0, 0, 0, snap.err
	}
	return snap.img, snap.hotX, snap.hotY, snap.serial, nil
}

// CursorPos returns the cursor screen position observed by the worker on
// its last sample. Errors out if the worker hasn't yet captured a frame
// or the most recent sample failed.
func (c *DesktopCapturer) CursorPos() (int, int, error) {
	snap := c.cursorState.load()
	if snap == nil {
		return 0, 0, fmt.Errorf("cursor position not sampled yet")
	}
	if snap.err != nil {
		return 0, 0, snap.err
	}
	if !snap.hasPos {
		return 0, 0, fmt.Errorf("cursor position unavailable")
	}
	return snap.posX, snap.posY, nil
}
