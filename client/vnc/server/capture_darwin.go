//go:build darwin && !ios

package server

import (
	"errors"
	"fmt"
	"hash/maphash"
	"image"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	log "github.com/sirupsen/logrus"
)

var darwinCaptureOnce sync.Once

var (
	cgMainDisplayID              func() uint32
	cgDisplayPixelsWide          func(uint32) uintptr
	cgDisplayPixelsHigh          func(uint32) uintptr
	cgDisplayCreateImage         func(uint32) uintptr
	cgImageGetWidth              func(uintptr) uintptr
	cgImageGetHeight             func(uintptr) uintptr
	cgImageGetBytesPerRow        func(uintptr) uintptr
	cgImageGetBitsPerPixel       func(uintptr) uintptr
	cgImageGetDataProvider       func(uintptr) uintptr
	cgDataProviderCopyData       func(uintptr) uintptr
	cgImageRelease               func(uintptr)
	cfDataGetLength              func(uintptr) int64
	cfDataGetBytePtr             func(uintptr) uintptr
	cfRelease                    func(uintptr)
	cgRequestScreenCaptureAccess func() bool
	cgEventCreate                func(uintptr) uintptr
	cgEventGetLocation           func(uintptr) cgPoint
	darwinCaptureReady           bool
)

// cgPoint mirrors CoreGraphics CGPoint: two doubles, 16 bytes, returned
// in registers on Darwin amd64/arm64. Used to receive cursor coordinates
// from CGEventGetLocation via purego.
type cgPoint struct {
	X, Y float64
}

func initDarwinCapture() {
	darwinCaptureOnce.Do(func() {
		cg, err := purego.Dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			log.Debugf("load CoreGraphics: %v", err)
			return
		}
		cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			log.Debugf("load CoreFoundation: %v", err)
			return
		}

		purego.RegisterLibFunc(&cgMainDisplayID, cg, "CGMainDisplayID")
		purego.RegisterLibFunc(&cgDisplayPixelsWide, cg, "CGDisplayPixelsWide")
		purego.RegisterLibFunc(&cgDisplayPixelsHigh, cg, "CGDisplayPixelsHigh")
		purego.RegisterLibFunc(&cgDisplayCreateImage, cg, "CGDisplayCreateImage")
		purego.RegisterLibFunc(&cgImageGetWidth, cg, "CGImageGetWidth")
		purego.RegisterLibFunc(&cgImageGetHeight, cg, "CGImageGetHeight")
		purego.RegisterLibFunc(&cgImageGetBytesPerRow, cg, "CGImageGetBytesPerRow")
		purego.RegisterLibFunc(&cgImageGetBitsPerPixel, cg, "CGImageGetBitsPerPixel")
		purego.RegisterLibFunc(&cgImageGetDataProvider, cg, "CGImageGetDataProvider")
		purego.RegisterLibFunc(&cgDataProviderCopyData, cg, "CGDataProviderCopyData")
		purego.RegisterLibFunc(&cgImageRelease, cg, "CGImageRelease")
		purego.RegisterLibFunc(&cfDataGetLength, cf, "CFDataGetLength")
		purego.RegisterLibFunc(&cfDataGetBytePtr, cf, "CFDataGetBytePtr")
		purego.RegisterLibFunc(&cfRelease, cf, "CFRelease")

		// CGRequestScreenCaptureAccess (macOS 11+) prompts on first call and
		// is a cheap no-op once granted. The Preflight companion is unreliable
		// on Sequoia (returns false even when access is granted), so we drive
		// the permission flow from actual capture failures instead.
		if sym, err := purego.Dlsym(cg, "CGRequestScreenCaptureAccess"); err == nil {
			purego.RegisterFunc(&cgRequestScreenCaptureAccess, sym)
		}
		// CGEventCreate / CGEventGetLocation feed the cursor position used
		// by remote-cursor compositing. Optional; absence reports as a
		// position-source error and disables that feature on this host.
		if sym, err := purego.Dlsym(cg, "CGEventCreate"); err == nil {
			purego.RegisterFunc(&cgEventCreate, sym)
		}
		if sym, err := purego.Dlsym(cg, "CGEventGetLocation"); err == nil {
			purego.RegisterFunc(&cgEventGetLocation, sym)
		}

		darwinCaptureReady = true
	})
}

// CGCapturer captures the macOS main display using Core Graphics.
type CGCapturer struct {
	displayID uint32
	w, h      int
	// downscale is 1 for pixel-perfect, 2 for Retina 2:1 box-filter downscale.
	downscale int
	hashSeed  maphash.Seed
	lastHash  uint64
	hasHash   bool
	// cursor lazily binds the private CGSCreateCurrentCursorImage symbol
	// so we can emit the Cursor pseudo-encoding without a per-frame cost
	// on builds that never query it.
	cursorOnce sync.Once
	cursor     *cgCursor
}

// PrimeScreenCapturePermission triggers the macOS Screen Recording
// permission prompt without creating a full capturer. The platform wiring
// calls this at VNC-server enable time so the user sees the prompt the
// moment they turn the feature on. CGRequestScreenCaptureAccess is a
// no-op when the grant already exists, so calling it on every enable is
// cheap and safe.
func PrimeScreenCapturePermission() {
	initDarwinCapture()
	if !darwinCaptureReady {
		return
	}
	if cgRequestScreenCaptureAccess != nil {
		cgRequestScreenCaptureAccess()
	}
}

// notifyScreenRecordingMissing nudges the user once per agent process to
// approve Screen Recording. The capturer init retries on backoff when the
// grant is missing; without the sync.Once we would reopen System Settings
// every tick and flood the daemon log with the same warning.
var screenRecordingNotifyOnce sync.Once

func notifyScreenRecordingMissing() {
	screenRecordingNotifyOnce.Do(func() {
		if cgRequestScreenCaptureAccess != nil {
			cgRequestScreenCaptureAccess()
		}
		openPrivacyPane("Privacy_ScreenCapture")
		log.Warn("Screen Recording permission not granted. " +
			"Opened System Settings > Privacy & Security > Screen Recording; enable netbird and restart.")
	})
}

// NewCGCapturer creates a screen capturer for the main display.
func NewCGCapturer() (*CGCapturer, error) {
	initDarwinCapture()
	if !darwinCaptureReady {
		return nil, fmt.Errorf("CoreGraphics not available")
	}

	displayID := cgMainDisplayID()
	c := &CGCapturer{displayID: displayID, downscale: 1, hashSeed: maphash.MakeSeed()}

	img, err := c.Capture()
	if err != nil {
		notifyScreenRecordingMissing()
		return nil, fmt.Errorf("probe capture: %w", err)
	}
	nativeW := img.Rect.Dx()
	nativeH := img.Rect.Dy()
	c.hasHash = false
	if nativeW == 0 || nativeH == 0 {
		return nil, errors.New("display dimensions are zero")
	}

	logicalW := int(cgDisplayPixelsWide(displayID))
	logicalH := int(cgDisplayPixelsHigh(displayID))

	// Enable 2:1 downscale on Retina unless explicitly disabled. Cuts pixel
	// count 4x, shrinking convert, diff, and wire data proportionally.
	if !retinaDownscaleDisabled() && nativeW >= 2*logicalW && nativeH >= 2*logicalH && nativeW%2 == 0 && nativeH%2 == 0 {
		c.downscale = 2
	}
	c.w = nativeW / c.downscale
	c.h = nativeH / c.downscale

	log.Infof("macOS capturer ready: %dx%d (native %dx%d, logical %dx%d, downscale=%d, display=%d)",
		c.w, c.h, nativeW, nativeH, logicalW, logicalH, c.downscale, displayID)
	return c, nil
}

func retinaDownscaleDisabled() bool {
	v := os.Getenv(EnvVNCDisableDownscale)
	if v == "" {
		return false
	}
	disabled, err := strconv.ParseBool(v)
	if err != nil {
		log.Warnf("parse %s: %v", EnvVNCDisableDownscale, err)
		return false
	}
	return disabled
}

// Width returns the screen width.
func (c *CGCapturer) Width() int { return c.w }

// Height returns the screen height.
func (c *CGCapturer) Height() int { return c.h }

// CaptureInto writes a fresh frame directly into dst, skipping the
// per-frame image.RGBA allocation that Capture() does. It always fills
// dst: the capturer is shared across all sessions, so dedup here would
// starve every consumer but the first one to poll after a change.
// Per-session prevFrame diffing in the session layer handles no-op frames.
func (c *CGCapturer) CaptureInto(dst *image.RGBA) error {
	cgImage := cgDisplayCreateImage(c.displayID)
	if cgImage == 0 {
		return fmt.Errorf("CGDisplayCreateImage returned nil (screen recording permission?)")
	}
	defer cgImageRelease(cgImage)
	w := int(cgImageGetWidth(cgImage))
	h := int(cgImageGetHeight(cgImage))
	bytesPerRow := int(cgImageGetBytesPerRow(cgImage))
	bpp := int(cgImageGetBitsPerPixel(cgImage))
	provider := cgImageGetDataProvider(cgImage)
	if provider == 0 {
		return fmt.Errorf("CGImageGetDataProvider returned nil")
	}
	cfData := cgDataProviderCopyData(provider)
	if cfData == 0 {
		return fmt.Errorf("CGDataProviderCopyData returned nil")
	}
	defer cfRelease(cfData)
	dataLen := int(cfDataGetLength(cfData))
	dataPtr := cfDataGetBytePtr(cfData)
	if dataPtr == 0 || dataLen == 0 {
		return fmt.Errorf("empty image data")
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), dataLen)

	ds := c.downscale
	if ds < 1 {
		ds = 1
	}
	outW := w / ds
	outH := h / ds
	if dst.Rect.Dx() != outW || dst.Rect.Dy() != outH {
		return fmt.Errorf("dst size mismatch: dst=%dx%d capturer=%dx%d",
			dst.Rect.Dx(), dst.Rect.Dy(), outW, outH)
	}
	bytesPerPixel := bpp / 8
	if bytesPerPixel == 4 && ds == 1 {
		convertBGRAToRGBA(dst.Pix, dst.Stride, src, bytesPerRow, w, h)
		return nil
	}
	if bytesPerPixel == 4 && ds == 2 {
		convertBGRAToRGBADownscale2(dst.Pix, dst.Stride, src, bytesPerRow, outW, outH)
		return nil
	}
	for row := 0; row < outH; row++ {
		srcOff := row * ds * bytesPerRow
		dstOff := row * dst.Stride
		for col := 0; col < outW; col++ {
			si := srcOff + col*ds*bytesPerPixel
			di := dstOff + col*4
			dst.Pix[di+0] = src[si+2]
			dst.Pix[di+1] = src[si+1]
			dst.Pix[di+2] = src[si+0]
			dst.Pix[di+3] = 0xff
		}
	}
	return nil
}

func (c *CGCapturer) Capture() (*image.RGBA, error) {
	cgImage := cgDisplayCreateImage(c.displayID)
	if cgImage == 0 {
		return nil, fmt.Errorf("CGDisplayCreateImage returned nil (screen recording permission?)")
	}
	defer cgImageRelease(cgImage)

	w := int(cgImageGetWidth(cgImage))
	h := int(cgImageGetHeight(cgImage))
	bytesPerRow := int(cgImageGetBytesPerRow(cgImage))
	bpp := int(cgImageGetBitsPerPixel(cgImage))

	provider := cgImageGetDataProvider(cgImage)
	if provider == 0 {
		return nil, fmt.Errorf("CGImageGetDataProvider returned nil")
	}

	cfData := cgDataProviderCopyData(provider)
	if cfData == 0 {
		return nil, fmt.Errorf("CGDataProviderCopyData returned nil")
	}
	defer cfRelease(cfData)

	dataLen := int(cfDataGetLength(cfData))
	dataPtr := cfDataGetBytePtr(cfData)
	if dataPtr == 0 || dataLen == 0 {
		return nil, fmt.Errorf("empty image data")
	}

	src := unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), dataLen)

	hash := maphash.Bytes(c.hashSeed, src)
	if c.hasHash && hash == c.lastHash {
		return nil, errFrameUnchanged
	}
	c.lastHash = hash
	c.hasHash = true

	ds := c.downscale
	if ds < 1 {
		ds = 1
	}
	outW := w / ds
	outH := h / ds
	img := image.NewRGBA(image.Rect(0, 0, outW, outH))

	bytesPerPixel := bpp / 8
	switch {
	case bytesPerPixel == 4 && ds == 1:
		convertBGRAToRGBA(img.Pix, img.Stride, src, bytesPerRow, w, h)
	case bytesPerPixel == 4 && ds == 2:
		convertBGRAToRGBADownscale2(img.Pix, img.Stride, src, bytesPerRow, outW, outH)
	default:
		convertBGRAToRGBAGeneric(img.Pix, img.Stride, src, bytesPerRow, bgraDownscaleParams{outW: outW, outH: outH, bytesPerPixel: bytesPerPixel, ds: ds})
	}

	return img, nil
}

type bgraDownscaleParams struct {
	outW, outH, bytesPerPixel, ds int
}

// convertBGRAToRGBAGeneric is the slow per-pixel fallback for non-4-bytes
// or non-1/2 downscale formats. Always available regardless of the source
// format quirks the fast paths optimize for.
func convertBGRAToRGBAGeneric(dst []byte, dstStride int, src []byte, srcStride int, p bgraDownscaleParams) {
	for row := 0; row < p.outH; row++ {
		srcOff := row * p.ds * srcStride
		dstOff := row * dstStride
		for col := 0; col < p.outW; col++ {
			si := srcOff + col*p.ds*p.bytesPerPixel
			di := dstOff + col*4
			dst[di+0] = src[si+2]
			dst[di+1] = src[si+1]
			dst[di+2] = src[si+0]
			dst[di+3] = 0xff
		}
	}
}

// convertBGRAToRGBADownscale2 averages every 2x2 BGRA block into one RGBA
// output pixel, parallelised across GOMAXPROCS cores. outW and outH are the
// destination dimensions (source is 2*outW by 2*outH).
func convertBGRAToRGBADownscale2(dst []byte, dstStride int, src []byte, srcStride, outW, outH int) {
	workers := runtime.GOMAXPROCS(0)
	if workers > outH {
		workers = outH
	}
	if workers < 1 || outH < 32 {
		workers = 1
	}

	convertRows := func(y0, y1 int) {
		for row := y0; row < y1; row++ {
			srcRow0 := 2 * row * srcStride
			srcRow1 := srcRow0 + srcStride
			dstOff := row * dstStride
			for col := 0; col < outW; col++ {
				s0 := srcRow0 + col*8
				s1 := srcRow1 + col*8
				b := (uint32(src[s0]) + uint32(src[s0+4]) + uint32(src[s1]) + uint32(src[s1+4])) >> 2
				g := (uint32(src[s0+1]) + uint32(src[s0+5]) + uint32(src[s1+1]) + uint32(src[s1+5])) >> 2
				r := (uint32(src[s0+2]) + uint32(src[s0+6]) + uint32(src[s1+2]) + uint32(src[s1+6])) >> 2
				di := dstOff + col*4
				dst[di+0] = byte(r)
				dst[di+1] = byte(g)
				dst[di+2] = byte(b)
				dst[di+3] = 0xff
			}
		}
	}

	if workers == 1 {
		convertRows(0, outH)
		return
	}

	var wg sync.WaitGroup
	chunk := (outH + workers - 1) / workers
	for i := 0; i < workers; i++ {
		y0 := i * chunk
		y1 := y0 + chunk
		if y1 > outH {
			y1 = outH
		}
		if y0 >= y1 {
			break
		}
		wg.Add(1)
		go func(y0, y1 int) {
			defer wg.Done()
			convertRows(y0, y1)
		}(y0, y1)
	}
	wg.Wait()
}

// convertBGRAToRGBA swaps R/B channels using uint32 word operations, and
// parallelises across GOMAXPROCS cores for large images.
func convertBGRAToRGBA(dst []byte, dstStride int, src []byte, srcStride, w, h int) {
	workers := runtime.GOMAXPROCS(0)
	if workers > h {
		workers = h
	}
	if workers < 1 || h < 64 {
		workers = 1
	}

	convertRows := func(y0, y1 int) {
		rowBytes := w * 4
		for row := y0; row < y1; row++ {
			dstRow := dst[row*dstStride : row*dstStride+rowBytes]
			srcRow := src[row*srcStride : row*srcStride+rowBytes]
			dstU := unsafe.Slice((*uint32)(unsafe.Pointer(&dstRow[0])), w)
			srcU := unsafe.Slice((*uint32)(unsafe.Pointer(&srcRow[0])), w)
			for i, p := range srcU {
				dstU[i] = (p & 0xff00ff00) | ((p & 0x000000ff) << 16) | ((p & 0x00ff0000) >> 16) | 0xff000000
			}
		}
	}

	if workers == 1 {
		convertRows(0, h)
		return
	}

	var wg sync.WaitGroup
	chunk := (h + workers - 1) / workers
	for i := 0; i < workers; i++ {
		y0 := i * chunk
		y1 := y0 + chunk
		if y1 > h {
			y1 = h
		}
		if y0 >= y1 {
			break
		}
		wg.Add(1)
		go func(y0, y1 int) {
			defer wg.Done()
			convertRows(y0, y1)
		}(y0, y1)
	}
	wg.Wait()
}

// MacPoller wraps CGCapturer with a staleness-cached on-demand Capture:
// sessions drive captures themselves from their encoder goroutine, so we
// don't need a background ticker. The last result is cached for a short
// window so concurrent sessions coalesce into one capture.
//
// The capturer is allocated lazily on first use and released when all
// clients disconnect. Init is retried with backoff because the user may
// grant Screen Recording permission while the server is already running.
type MacPoller struct {
	mu sync.Mutex

	capturer *CGCapturer
	w, h     int

	lastFrame *image.RGBA
	lastAt    time.Time

	clients          atomic.Int32
	initFails        int
	initBackoffUntil time.Time
	closed           bool
}

// macInitRetryBackoffFor returns the delay we wait between init attempts
// after consecutive failures. Screen Recording permission is a one-shot
// user grant, so after several failures we back off aggressively.
func macInitRetryBackoffFor(fails int) time.Duration {
	switch {
	case fails > 15:
		return 30 * time.Second
	case fails > 5:
		return 10 * time.Second
	default:
		return 2 * time.Second
	}
}

// NewMacPoller creates a lazy on-demand capturer for the macOS display.
func NewMacPoller() *MacPoller {
	return &MacPoller{}
}

// Wake is a no-op retained for API compatibility. With on-demand capture
// there is no background retry loop to kick: init happens on the next
// Capture/ClientConnect call.
func (p *MacPoller) Wake() {
	// intentional no-op
}

// ClientConnect increments the active client count and eagerly initialises
// the capturer so the first FBUpdateRequest doesn't pay the init cost.
func (p *MacPoller) ClientConnect() {
	if p.clients.Add(1) == 1 {
		p.mu.Lock()
		_ = p.ensureCapturerLocked()
		p.mu.Unlock()
	}
}

// ClientDisconnect decrements the active client count. On the last
// disconnect the capturer is released.
func (p *MacPoller) ClientDisconnect() {
	if p.clients.Add(-1) == 0 {
		p.mu.Lock()
		p.capturer = nil
		p.lastFrame = nil
		p.mu.Unlock()
	}
}

// Close releases all resources.
func (p *MacPoller) Close() {
	p.mu.Lock()
	p.closed = true
	p.capturer = nil
	p.lastFrame = nil
	p.mu.Unlock()
}

// Width returns the screen width. Triggers lazy init if needed.
func (p *MacPoller) Width() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.ensureCapturerLocked()
	return p.w
}

// Height returns the screen height. Triggers lazy init if needed.
func (p *MacPoller) Height() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.ensureCapturerLocked()
	return p.h
}

// CaptureInto fills dst directly via the underlying capturer, bypassing
// the freshness cache.
func (p *MacPoller) CaptureInto(dst *image.RGBA) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ensureCapturerLocked(); err != nil {
		return err
	}
	if err := p.capturer.CaptureInto(dst); err != nil {
		p.capturer = nil
		return fmt.Errorf("macos capture: %w", err)
	}
	return nil
}

// Capture returns a fresh frame, serving from the short-lived cache if a
// previous caller captured within freshWindow. Handles the
// errFrameUnchanged return from CGCapturer by reusing the cached frame.
func (p *MacPoller) Capture() (*image.RGBA, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.lastFrame != nil && time.Since(p.lastAt) < freshWindow {
		return p.lastFrame, nil
	}
	if err := p.ensureCapturerLocked(); err != nil {
		return nil, err
	}
	img, err := p.capturer.Capture()
	if errors.Is(err, errFrameUnchanged) {
		if p.lastFrame != nil {
			p.lastAt = time.Now()
			return p.lastFrame, nil
		}
		return nil, err
	}
	if err != nil {
		// Drop the capturer so the next call retries init; the display stream
		// can die if the session changes or permissions are revoked.
		p.capturer = nil
		return nil, fmt.Errorf("macos capture: %w", err)
	}
	p.lastFrame = img
	p.lastAt = time.Now()
	return img, nil
}

// ensureCapturerLocked initialises the underlying CGCapturer if needed.
// Caller must hold p.mu.
func (p *MacPoller) ensureCapturerLocked() error {
	if p.closed {
		return fmt.Errorf("poller closed")
	}
	if p.capturer != nil {
		return nil
	}
	if time.Now().Before(p.initBackoffUntil) {
		return fmt.Errorf("macOS capturer unavailable (retry scheduled)")
	}
	c, err := NewCGCapturer()
	if err != nil {
		p.initFails++
		p.initBackoffUntil = time.Now().Add(macInitRetryBackoffFor(p.initFails))
		if p.initFails == 1 || p.initFails%10 == 0 {
			log.Warnf("macOS capturer: %v (attempt %d)", err, p.initFails)
		} else {
			log.Debugf("macOS capturer: %v (attempt %d)", err, p.initFails)
		}
		return err
	}
	p.initFails = 0
	p.capturer = c
	p.w, p.h = c.Width(), c.Height()
	return nil
}

var _ ScreenCapturer = (*MacPoller)(nil)
