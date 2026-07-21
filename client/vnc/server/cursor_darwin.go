//go:build darwin && !ios

package server

import (
	"fmt"
	"hash/maphash"
	"image"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	log "github.com/sirupsen/logrus"
)

var (
	darwinCursorOnce sync.Once
	cgsCreateCursor  func() uintptr
	darwinCursorErr  error
)

// initDarwinCursor binds a private symbol that returns the current
// system cursor image. The classic CGSCreateCurrentCursorImage moved
// from CoreGraphics to SkyLight around macOS 13 and is gone entirely
// in Sequoia; we probe both frameworks for any of the historical
// names so this keeps working on whichever release the binding still
// exists. Without a hit the remote-cursor compositing path becomes a
// no-op and we log the candidates we tried.
func initDarwinCursor() {
	darwinCursorOnce.Do(func() {
		libs := []string{
			"/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight",
			"/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
		}
		names := []string{
			"CGSCreateCurrentCursorImage",
			"CGSCopyCurrentCursorImage",
			"CGSCurrentCursorImage",
			"CGSHardwareCursorActiveImage",
		}
		var tried []string
		for _, path := range libs {
			h, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
			if err != nil {
				tried = append(tried, fmt.Sprintf("dlopen %s: %v", path, err))
				continue
			}
			for _, name := range names {
				sym, err := purego.Dlsym(h, name)
				if err != nil {
					tried = append(tried, fmt.Sprintf("%s!%s missing", path, name))
					continue
				}
				purego.RegisterFunc(&cgsCreateCursor, sym)
				log.Infof("macOS cursor: bound %s from %s", name, path)
				return
			}
		}
		darwinCursorErr = fmt.Errorf("no cursor image symbol available; tried: %v", tried)
	})
}

// cgCursor holds the cached macOS cursor sprite and bumps a serial when
// the bytes change. Hotspot is left at (0, 0): the public Cocoa hot-spot
// query lives on NSCursor which is process-local and not reachable from
// our purego-based bindings; the visual cost is a small misalignment for
// non-arrow cursors (I-beam, crosshair, etc.).
type cgCursor struct {
	mu       sync.Mutex
	hashSeed maphash.Seed
	lastSum  uint64
	cached   *image.RGBA
	serial   uint64
}

func newCGCursor() *cgCursor {
	initDarwinCursor()
	return &cgCursor{hashSeed: maphash.MakeSeed()}
}

// Cursor returns the current cursor sprite as RGBA. Errors that come from
// missing private symbols are sticky; transient empty-image responses are
// reported as such so the encoder skips this cycle.
func (c *cgCursor) Cursor() (*image.RGBA, int, int, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if darwinCursorErr != nil {
		return nil, 0, 0, 0, darwinCursorErr
	}
	if cgsCreateCursor == nil {
		return nil, 0, 0, 0, fmt.Errorf("CGSCreateCurrentCursorImage unavailable")
	}
	cgImage := cgsCreateCursor()
	if cgImage == 0 {
		return nil, 0, 0, 0, fmt.Errorf("no cursor image available")
	}
	defer cgImageRelease(cgImage)

	w := int(cgImageGetWidth(cgImage))
	h := int(cgImageGetHeight(cgImage))
	if w <= 0 || h <= 0 {
		return nil, 0, 0, 0, fmt.Errorf("cursor has zero extent")
	}
	bytesPerRow := int(cgImageGetBytesPerRow(cgImage))
	bpp := int(cgImageGetBitsPerPixel(cgImage))
	if bpp != 32 {
		return nil, 0, 0, 0, fmt.Errorf("unsupported cursor bpp: %d", bpp)
	}
	provider := cgImageGetDataProvider(cgImage)
	if provider == 0 {
		return nil, 0, 0, 0, fmt.Errorf("cursor data provider missing")
	}
	cfData := cgDataProviderCopyData(provider)
	if cfData == 0 {
		return nil, 0, 0, 0, fmt.Errorf("cursor data copy failed")
	}
	defer cfRelease(cfData)
	dataLen := int(cfDataGetLength(cfData))
	dataPtr := cfDataGetBytePtr(cfData)
	if dataPtr == 0 || dataLen == 0 {
		return nil, 0, 0, 0, fmt.Errorf("cursor data empty")
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), dataLen)

	sum := maphash.Bytes(c.hashSeed, src)
	if c.cached != nil && sum == c.lastSum {
		return c.cached, 0, 0, c.serial, nil
	}

	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		srcOff := y * bytesPerRow
		dstOff := y * w * 4
		for x := 0; x < w; x++ {
			si := srcOff + x*4
			di := dstOff + x*4
			img.Pix[di+0] = src[si+2]
			img.Pix[di+1] = src[si+1]
			img.Pix[di+2] = src[si+0]
			img.Pix[di+3] = src[si+3]
		}
	}

	c.lastSum = sum
	c.cached = img
	c.serial++
	return img, 0, 0, c.serial, nil
}

// Cursor on CGCapturer satisfies cursorSource. The cgCursor wrapper is
// allocated lazily so a build that never asks for the cursor pays no cost.
func (c *CGCapturer) Cursor() (*image.RGBA, int, int, uint64, error) {
	c.cursorOnce.Do(func() {
		c.cursor = newCGCursor()
	})
	return c.cursor.Cursor()
}

// CursorPos returns the current global mouse location via CGEventCreate /
// CGEventGetLocation. Coordinates are screen pixels in the main display.
func (c *CGCapturer) CursorPos() (int, int, error) {
	if cgEventCreate == nil || cgEventGetLocation == nil {
		return 0, 0, fmt.Errorf("CGEvent location APIs unavailable")
	}
	ev := cgEventCreate(0)
	if ev == 0 {
		return 0, 0, fmt.Errorf("CGEventCreate returned nil")
	}
	defer cfRelease(ev)
	pt := cgEventGetLocation(ev)
	return int(pt.X), int(pt.Y), nil
}

// Cursor on MacPoller forwards to the lazy CGCapturer. ensureCapturerLocked
// returns an error when Screen Recording permission has not been granted;
// in that case there is no usable cursor source either.
func (p *MacPoller) Cursor() (*image.RGBA, int, int, uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureCapturerLocked(); err != nil {
		return nil, 0, 0, 0, err
	}
	return p.capturer.Cursor()
}

// CursorPos forwards to the lazy CGCapturer.
func (p *MacPoller) CursorPos() (int, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureCapturerLocked(); err != nil {
		return 0, 0, err
	}
	return p.capturer.CursorPos()
}
