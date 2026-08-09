//go:build windows

package server

import (
	"fmt"
	"image"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")
	user32 = windows.NewLazySystemDLL("user32.dll")

	procGetDC            = user32.NewProc("GetDC")
	procReleaseDC        = user32.NewProc("ReleaseDC")
	procCreateCompatDC   = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection = gdi32.NewProc("CreateDIBSection")
	procSelectObject     = gdi32.NewProc("SelectObject")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
	procDeleteDC         = gdi32.NewProc("DeleteDC")
	procBitBlt           = gdi32.NewProc("BitBlt")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")

	// Desktop switching for service/Session 0 capture.
	procOpenInputDesktop          = user32.NewProc("OpenInputDesktop")
	procSetThreadDesktop          = user32.NewProc("SetThreadDesktop")
	procCloseDesktop              = user32.NewProc("CloseDesktop")
	procOpenWindowStation         = user32.NewProc("OpenWindowStationW")
	procSetProcessWindowStation   = user32.NewProc("SetProcessWindowStation")
	procCloseWindowStation        = user32.NewProc("CloseWindowStation")
	procGetUserObjectInformationW = user32.NewProc("GetUserObjectInformationW")
)

const uoiName = 2

const (
	smCxScreen   = 0
	smCyScreen   = 1
	srccopy      = 0x00CC0020
	captureBlt   = 0x40000000
	dibRgbColors = 0
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type bitmapInfo struct {
	Header bitmapInfoHeader
}

// setupInteractiveWindowStation associates the current process with WinSta0,
// the interactive window station. This is required for a SYSTEM service in
// Session 0 to call OpenInputDesktop for screen capture and input injection.
func setupInteractiveWindowStation() error {
	name, err := windows.UTF16PtrFromString("WinSta0")
	if err != nil {
		return fmt.Errorf("UTF16 WinSta0: %w", err)
	}
	hWinSta, _, err := procOpenWindowStation.Call(
		uintptr(unsafe.Pointer(name)),
		0,
		uintptr(windows.MAXIMUM_ALLOWED),
	)
	if hWinSta == 0 {
		return fmt.Errorf("OpenWindowStation(WinSta0): %w", err)
	}
	r, _, err := procSetProcessWindowStation.Call(hWinSta)
	if r == 0 {
		_, _, _ = procCloseWindowStation.Call(hWinSta)
		return fmt.Errorf("SetProcessWindowStation: %w", err)
	}
	log.Info("process window station set to WinSta0 (interactive)")
	return nil
}

func screenSize() (int, int) {
	w, _, _ := procGetSystemMetrics.Call(uintptr(smCxScreen))
	h, _, _ := procGetSystemMetrics.Call(uintptr(smCyScreen))
	return int(w), int(h)
}

func getDesktopName(hDesk uintptr) string {
	var buf [256]uint16
	var needed uint32
	_, _, _ = procGetUserObjectInformationW.Call(hDesk, uoiName,
		uintptr(unsafe.Pointer(&buf[0])), 512,
		uintptr(unsafe.Pointer(&needed)))
	return windows.UTF16ToString(buf[:])
}

// switchToInputDesktop opens the desktop currently receiving user input
// and sets it as the calling OS thread's desktop. Must be called from a
// goroutine locked to its OS thread via runtime.LockOSThread().
func switchToInputDesktop() (bool, string) {
	hDesk, _, _ := procOpenInputDesktop.Call(0, 0, uintptr(windows.MAXIMUM_ALLOWED))
	if hDesk == 0 {
		return false, ""
	}
	name := getDesktopName(hDesk)
	ret, _, _ := procSetThreadDesktop.Call(hDesk)
	_, _, _ = procCloseDesktop.Call(hDesk)
	return ret != 0, name
}

// gdiCapturer captures the desktop screen using GDI BitBlt.
// GDI objects (DC, DIBSection) are allocated once and reused across frames.
type gdiCapturer struct {
	mu     sync.Mutex
	width  int
	height int

	// Pre-allocated GDI resources, reused across captures.
	memDC uintptr
	bmp   uintptr
	bits  uintptr
}

func newGDICapturer() (*gdiCapturer, error) {
	w, h := screenSize()
	if w == 0 || h == 0 {
		return nil, fmt.Errorf("screen dimensions are zero")
	}
	c := &gdiCapturer{width: w, height: h}
	if err := c.allocGDI(); err != nil {
		return nil, err
	}
	return c, nil
}

// allocGDI pre-allocates the compatible DC and DIB section for reuse.
func (c *gdiCapturer) allocGDI() error {
	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return fmt.Errorf("GetDC returned 0")
	}
	defer func() { _, _, _ = procReleaseDC.Call(0, screenDC) }()

	memDC, _, _ := procCreateCompatDC.Call(screenDC)
	if memDC == 0 {
		return fmt.Errorf("CreateCompatibleDC returned 0")
	}

	bi := bitmapInfo{
		Header: bitmapInfoHeader{
			Size:     uint32(unsafe.Sizeof(bitmapInfoHeader{})),
			Width:    int32(c.width),
			Height:   -int32(c.height), // negative = top-down DIB
			Planes:   1,
			BitCount: 32,
		},
	}

	var bits uintptr
	bmp, _, _ := procCreateDIBSection.Call(
		screenDC,
		uintptr(unsafe.Pointer(&bi)),
		dibRgbColors,
		uintptr(unsafe.Pointer(&bits)),
		0, 0,
	)
	if bmp == 0 || bits == 0 {
		_, _, _ = procDeleteDC.Call(memDC)
		return fmt.Errorf("CreateDIBSection returned 0")
	}

	_, _, _ = procSelectObject.Call(memDC, bmp)

	c.memDC = memDC
	c.bmp = bmp
	c.bits = bits
	return nil
}

func (c *gdiCapturer) close() { c.freeGDI() }

// freeGDI releases pre-allocated GDI resources.
func (c *gdiCapturer) freeGDI() {
	if c.bmp != 0 {
		_, _, _ = procDeleteObject.Call(c.bmp)
		c.bmp = 0
	}
	if c.memDC != 0 {
		_, _, _ = procDeleteDC.Call(c.memDC)
		c.memDC = 0
	}
	c.bits = 0
}

func (c *gdiCapturer) capture() (*image.RGBA, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.memDC == 0 {
		return nil, fmt.Errorf("GDI resources not allocated")
	}

	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return nil, fmt.Errorf("GetDC returned 0")
	}
	defer func() { _, _, _ = procReleaseDC.Call(0, screenDC) }()

	// SRCCOPY|CAPTUREBLT: CAPTUREBLT forces inclusion of layered/topmost
	// windows in the capture and is required for GDI BitBlt to return live
	// pixels when the session is rendered through RDP / DWM-composited
	// surfaces. Without it BitBlt reads the backing-store DIB which is
	// often empty (all-black) on RDP and headless sessions.
	ret, _, _ := procBitBlt.Call(c.memDC, 0, 0, uintptr(c.width), uintptr(c.height),
		screenDC, 0, 0, srccopy|captureBlt)
	if ret == 0 {
		return nil, fmt.Errorf("BitBlt returned 0")
	}

	n := c.width * c.height * 4
	raw := unsafe.Slice((*byte)(unsafe.Pointer(c.bits)), n)

	// GDI gives BGRA, the RFB encoder expects RGBA (img.Pix layout).
	// Swap R and B in bulk using uint32 operations (one load + mask + shift
	// per pixel instead of three separate byte assignments).
	img := image.NewRGBA(image.Rect(0, 0, c.width, c.height))
	swizzleBGRAtoRGBA(img.Pix, raw)
	return img, nil
}

// DesktopCapturer captures the interactive desktop, handling desktop transitions
// (login screen, UAC prompts). A dedicated OS-locked goroutine continuously
// captures frames on demand via a dedicated OS-locked goroutine (required
// because DXGI's D3D11 device context is not thread-safe). Sessions drive
// timing by calling Capture(); a short staleness cache coalesces concurrent
// requests. Capture pauses automatically when no clients are connected.
type DesktopCapturer struct {
	mu   sync.Mutex
	w, h int

	// lastFrame/lastAt implement a small staleness cache so multiple
	// near-simultaneous Capture calls share one DXGI round-trip.
	lastFrame *image.RGBA
	lastAt    time.Time

	// clients tracks the number of active VNC sessions. When zero, the
	// worker goroutine releases the underlying capturer.
	clients atomic.Int32

	// reqCh carries capture requests from sessions to the OS-locked worker.
	reqCh chan captureReq
	// wake is signaled when a client connects and the worker should resume.
	wake chan struct{}
	// done is closed when Close is called, terminating the worker.
	done chan struct{}

	// cursorState holds the latest cursor sprite sampled by the worker.
	// The worker calls GetCursorInfo every capture and decodes a new
	// sprite only when the HCURSOR changes.
	cursorState cursorState
}

// captureReq is a single capture request awaiting a reply. Reply channel is
// buffered to size 1 so the worker never blocks on a sender that's gone.
type captureReq struct {
	reply chan captureReply
}

type captureReply struct {
	img *image.RGBA
	err error
}

// NewDesktopCapturer creates an on-demand capturer for the active desktop.
func NewDesktopCapturer() *DesktopCapturer {
	c := &DesktopCapturer{
		wake:  make(chan struct{}, 1),
		done:  make(chan struct{}),
		reqCh: make(chan captureReq),
	}
	go c.worker()
	return c
}

// ClientConnect increments the active client count, resuming capture if needed.
func (c *DesktopCapturer) ClientConnect() {
	c.clients.Add(1)
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// ClientDisconnect decrements the active client count.
func (c *DesktopCapturer) ClientDisconnect() {
	c.clients.Add(-1)
}

// Close stops the capture loop and releases resources.
func (c *DesktopCapturer) Close() {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
}

// Width returns the current screen width, triggering a capture if the
// worker hasn't initialised yet. validateCapturer depends on Width/Height
// becoming non-zero promptly after ClientConnect so it doesn't reject
// brand-new sessions.
func (c *DesktopCapturer) Width() int {
	c.mu.Lock()
	w := c.w
	c.mu.Unlock()
	if w == 0 && c.clients.Load() > 0 {
		_, _ = c.Capture()
		c.mu.Lock()
		w = c.w
		c.mu.Unlock()
	}
	return w
}

// Height returns the current screen height, triggering a capture if the
// worker hasn't initialised yet (see Width). Returns 0 while no client is
// connected so callers don't deadlock against a parked worker.
func (c *DesktopCapturer) Height() int {
	c.mu.Lock()
	h := c.h
	c.mu.Unlock()
	if h == 0 && c.clients.Load() > 0 {
		_, _ = c.Capture()
		c.mu.Lock()
		h = c.h
		c.mu.Unlock()
	}
	return h
}

// Capture returns a freshly captured frame, serving from a short staleness
// cache when multiple sessions ask within freshWindow of each other. All
// real DXGI/GDI work happens on the OS-locked worker goroutine.
func (c *DesktopCapturer) Capture() (*image.RGBA, error) {
	c.mu.Lock()
	if c.lastFrame != nil && time.Since(c.lastAt) < freshWindow {
		img := c.lastFrame
		c.mu.Unlock()
		return img, nil
	}
	c.mu.Unlock()

	reply := make(chan captureReply, 1)
	select {
	case c.reqCh <- captureReq{reply: reply}:
	case <-c.done:
		return nil, fmt.Errorf("capturer closed")
	}
	select {
	case r := <-reply:
		if r.err != nil {
			return nil, r.err
		}
		c.mu.Lock()
		c.lastFrame = r.img
		c.lastAt = time.Now()
		c.mu.Unlock()
		return r.img, nil
	case <-c.done:
		return nil, fmt.Errorf("capturer closed")
	}
}

// waitForClient blocks until a client connects or the capturer is closed.
func (c *DesktopCapturer) waitForClient() bool {
	if c.clients.Load() > 0 {
		return true
	}
	select {
	case <-c.wake:
		return true
	case <-c.done:
		return false
	}
}

// worker owns DXGI/GDI state on its OS-locked thread and services capture
// requests from sessions. No background ticker: a capture happens only when
// a session asks for one (throttled by Capture()'s staleness cache).
func (c *DesktopCapturer) worker() {
	runtime.LockOSThread()

	// When running as a Windows service (Session 0), we need to attach to the
	// interactive window station before OpenInputDesktop will succeed.
	if err := setupInteractiveWindowStation(); err != nil {
		log.Warnf("attach to interactive window station: %v", err)
	}

	w := &captureWorker{c: c}
	defer w.closeCapturer()

	for {
		if !c.waitForClient() {
			return
		}
		// Drop the capturer when all clients have disconnected so we don't
		// hold the DXGI duplication or GDI DC on an idle peer.
		if c.clients.Load() <= 0 {
			w.closeCapturer()
			continue
		}
		if !w.handleNextRequest() {
			return
		}
	}
}

// frameCapturer is the per-backend interface used by the worker. DXGI and
// GDI implementations both satisfy it.
type frameCapturer interface {
	capture() (*image.RGBA, error)
	close()
}

// captureWorker owns the worker goroutine's mutable state. Extracted into a
// struct so the request/desktop/init logic can live on small methods and the
// outer worker() stays a thin loop.
type captureWorker struct {
	c             *DesktopCapturer
	cap           frameCapturer
	desktopFails  int
	lastDesktop   string
	nextInitRetry time.Time
	cursor        cursorSampler
	// lastBackend records the last capturer kind that came out of
	// createCapturer ("dxgi" or "gdi"); used to demote repeat "using X"
	// and DXGI-unavailable logs to debug when nothing changed.
	lastBackend string
	// lastDXGIErr is the textual DXGI failure printed in the most recent
	// fallback warning; suppresses repeat warns when DXGI keeps failing
	// the same way across desktop changes (login -> lock -> login).
	lastDXGIErr string
}

// handleNextRequest waits for either shutdown or a capture request and runs
// the request through prepCapturer/capture. Returns false when the worker
// should exit.
func (w *captureWorker) handleNextRequest() bool {
	select {
	case <-w.c.done:
		return false
	case req := <-w.c.reqCh:
		w.serveRequest(req)
		return true
	}
}

func (w *captureWorker) serveRequest(req captureReq) {
	fc, err := w.prepCapturer()
	if err != nil {
		req.reply <- captureReply{err: err}
		return
	}
	img, err := fc.capture()
	if err != nil {
		log.Debugf("capture: %v", err)
		w.closeCapturer()
		w.nextInitRetry = time.Now().Add(100 * time.Millisecond)
		req.reply <- captureReply{err: err}
		return
	}
	if snap, err := w.cursor.sample(); err != nil {
		w.c.cursorState.store(&cursorSnapshot{err: err})
	} else {
		w.c.cursorState.store(snap)
	}
	req.reply <- captureReply{img: img}
}

// prepCapturer switches to the input desktop, handles desktop-change
// teardown, and creates the underlying capturer on demand. Backoff state is
// tracked across calls via w.nextInitRetry.
func (w *captureWorker) prepCapturer() (frameCapturer, error) {
	if err := w.refreshDesktop(); err != nil {
		return nil, err
	}
	if w.cap != nil {
		return w.cap, nil
	}
	if time.Now().Before(w.nextInitRetry) {
		return nil, fmt.Errorf("capturer init backing off")
	}
	fc, err := w.createCapturer()
	if err != nil {
		w.nextInitRetry = time.Now().Add(500 * time.Millisecond)
		return nil, err
	}
	w.cap = fc
	sw, sh := screenSize()
	w.c.mu.Lock()
	sizeChanged := w.c.w != sw || w.c.h != sh
	w.c.w, w.c.h = sw, sh
	w.c.mu.Unlock()
	if sizeChanged {
		log.Infof("screen capturer ready: %dx%d", sw, sh)
	} else {
		log.Debugf("screen capturer ready: %dx%d", sw, sh)
	}
	return w.cap, nil
}

// refreshDesktop tracks the active input desktop. When it changes (lock
// screen, fast-user-switch) the existing capturer is dropped so the next
// call rebuilds one against the new desktop.
func (w *captureWorker) refreshDesktop() error {
	ok, desk := switchToInputDesktop()
	if !ok {
		w.desktopFails++
		if w.desktopFails == 1 || w.desktopFails%100 == 0 {
			log.Warnf("switchToInputDesktop failed (count=%d), no interactive desktop session?", w.desktopFails)
		}
		return fmt.Errorf("no interactive desktop")
	}
	if w.desktopFails > 0 {
		log.Infof("switchToInputDesktop recovered after %d failures, desktop=%q", w.desktopFails, desk)
		w.desktopFails = 0
	}
	if desk != w.lastDesktop {
		log.Infof("desktop changed: %q -> %q", w.lastDesktop, desk)
		w.lastDesktop = desk
		w.closeCapturer()
	}
	return nil
}

func (w *captureWorker) createCapturer() (frameCapturer, error) {
	dc, err := newDXGICapturer()
	if err == nil {
		if w.lastBackend != "dxgi" {
			log.Info("using DXGI Desktop Duplication for capture")
		} else {
			log.Debug("using DXGI Desktop Duplication for capture")
		}
		w.lastBackend = "dxgi"
		w.lastDXGIErr = ""
		return dc, nil
	}
	errStr := err.Error()
	if errStr != w.lastDXGIErr {
		log.Warnf("DXGI Desktop Duplication unavailable, falling back to slower GDI BitBlt: %v", err)
		w.lastDXGIErr = errStr
	} else {
		log.Debugf("DXGI Desktop Duplication still unavailable, falling back to slower GDI BitBlt: %v", err)
	}
	gc, err := newGDICapturer()
	if err != nil {
		return nil, err
	}
	if w.lastBackend != "gdi" {
		log.Info("using GDI BitBlt for capture")
	} else {
		log.Debug("using GDI BitBlt for capture")
	}
	w.lastBackend = "gdi"
	return gc, nil
}

func (w *captureWorker) closeCapturer() {
	if w.cap != nil {
		w.cap.close()
		w.cap = nil
	}
}
