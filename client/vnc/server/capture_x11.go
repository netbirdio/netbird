//go:build (linux && !android) || freebsd

package server

import (
	"fmt"
	"image"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
)

const (
	// x11SocketDir is the well-known directory where X servers create
	// their abstract UNIX-domain sockets, named "X<display>". Used both
	// for auto-detecting an existing display and for placing/probing
	// sockets of virtual sessions we spawn.
	x11SocketDir = "/tmp/.X11-unix"

	// envDisplay is the X11 display selector environment variable.
	envDisplay = "DISPLAY"
	// envXAuthority points X clients at the cookie file used to
	// authenticate against the running X server.
	envXAuthority = "XAUTHORITY"
)

// X11Capturer captures the screen from an X11 display using the MIT-SHM extension.
type X11Capturer struct {
	mu      sync.Mutex
	conn    *xgb.Conn
	screen  *xproto.ScreenInfo
	w, h    int
	shmID   int
	shmAddr []byte
	shmSeg  uint32
	useSHM  bool
	// bufs double-buffers output images so the X11Poller's capture loop can
	// overwrite one while the session is still encoding the other. Before
	// this, a single reused buffer would race with the reader. Allocation
	// happens on first use and on geometry change.
	bufs [2]*image.RGBA
	cur  int
	// cursor is the XFixes binding used to report the current sprite.
	// Allocated lazily on the first Cursor call. cursorInitErr latches
	// a permanent init failure so we stop retrying every frame.
	cursor        *xfixesCursor
	cursorInitErr error
}

// detectX11Display finds the active X11 display and sets DISPLAY/XAUTHORITY
// environment variables if needed. This is required when running as a system
// service where these vars aren't set.
func detectX11Display() {
	if os.Getenv(envDisplay) != "" {
		return
	}

	// Try /proc first (Linux), then ps fallback (FreeBSD and others).
	if detectX11FromProc() {
		return
	}
	if detectX11FromSockets() {
		return
	}
}

// detectX11FromProc scans /proc/*/cmdline for Xorg (Linux).
func detectX11FromProc() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if display, auth := parseXorgArgs(splitCmdline(cmdline)); display != "" {
			setDisplayEnv(display, auth)
			return true
		}
	}
	return false
}

// detectX11FromSockets checks /tmp/.X11-unix/ for X sockets and uses ps
// to find the auth file. Works on FreeBSD and other systems without /proc.
func detectX11FromSockets() bool {
	entries, err := os.ReadDir(x11SocketDir)
	if err != nil {
		return false
	}

	// Pick the lowest numeric display rather than the lexically first
	// entry, so X10 doesn't win over X2.
	minDisplay := -1
	for _, e := range entries {
		name := e.Name()
		if len(name) < 2 || name[0] != 'X' {
			continue
		}
		n, err := strconv.Atoi(name[1:])
		if err != nil {
			continue
		}
		if minDisplay < 0 || n < minDisplay {
			minDisplay = n
		}
	}
	if minDisplay < 0 {
		return false
	}
	display := ":" + strconv.Itoa(minDisplay)
	os.Setenv(envDisplay, display)
	auth := findXorgAuthFromPS()
	if auth != "" {
		os.Setenv(envXAuthority, auth)
		log.Infof("auto-detected DISPLAY=%s (from socket) XAUTHORITY=%s (from ps)", display, auth)
	} else {
		log.Infof("auto-detected DISPLAY=%s (from socket)", display)
	}
	return true
}

// findXorgAuthFromPS runs ps to find Xorg and extract its -auth argument.
func findXorgAuthFromPS() string {
	out, err := exec.Command("ps", "auxww").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "Xorg") && !strings.Contains(line, "/X ") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "-auth" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return ""
}

func parseXorgArgs(args []string) (display, auth string) {
	if len(args) == 0 {
		return "", ""
	}
	base := args[0]
	if !(base == "Xorg" || base == "X" || len(base) > 0 && base[len(base)-1] == 'X' ||
		strings.Contains(base, "/Xorg") || strings.Contains(base, "/X")) {
		return "", ""
	}
	for i, arg := range args[1:] {
		if len(arg) > 0 && arg[0] == ':' {
			display = arg
		}
		if arg == "-auth" && i+2 < len(args) {
			auth = args[i+2]
		}
	}
	return display, auth
}

func setDisplayEnv(display, auth string) {
	os.Setenv(envDisplay, display)
	if auth != "" {
		os.Setenv(envXAuthority, auth)
		log.Infof("auto-detected DISPLAY=%s XAUTHORITY=%s", display, auth)
		return
	}
	log.Infof("auto-detected DISPLAY=%s", display)
}

func splitCmdline(data []byte) []string {
	var args []string
	for _, b := range splitNull(data) {
		if len(b) > 0 {
			args = append(args, string(b))
		}
	}
	return args
}

func splitNull(data []byte) [][]byte {
	var parts [][]byte
	start := 0
	for i, b := range data {
		if b == 0 {
			parts = append(parts, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		parts = append(parts, data[start:])
	}
	return parts
}

// NewX11Capturer connects to the X11 display and sets up shared memory capture.
// Empty cookieHex falls back to XAUTHORITY env lookup.
func NewX11Capturer(display, cookieHex string) (*X11Capturer, error) {
	if display == "" {
		detectX11Display()
		display = os.Getenv(envDisplay)
	}
	if display == "" {
		return nil, fmt.Errorf("DISPLAY not set and no Xorg process found")
	}

	var conn *xgb.Conn
	var err error
	if cookieHex != "" {
		conn, err = dialXUnixWithCookie(display, cookieHex)
	} else {
		conn, err = xgb.NewConnDisplay(display)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to X11 display %s: %w", display, err)
	}

	setup := xproto.Setup(conn)
	if len(setup.Roots) == 0 {
		conn.Close()
		return nil, fmt.Errorf("no X11 screens")
	}
	screen := setup.Roots[0]

	c := &X11Capturer{
		conn:   conn,
		screen: &screen,
		w:      int(screen.WidthInPixels),
		h:      int(screen.HeightInPixels),
	}

	if err := c.initSHM(); err != nil {
		log.Debugf("X11 SHM not available, using slow GetImage: %v", err)
	}

	log.Infof("X11 capturer ready: %dx%d (display=%s, shm=%v)", c.w, c.h, display, c.useSHM)
	return c, nil
}

// initSHM is implemented in capture_x11_shm_linux.go (requires SysV SHM).
// On platforms without SysV SHM (FreeBSD), a stub returns an error and
// the capturer falls back to GetImage.

// Width returns the screen width.
func (c *X11Capturer) Width() int { return c.w }

// Height returns the screen height.
func (c *X11Capturer) Height() int { return c.h }

// Capture returns the current screen as an RGBA image.
func (c *X11Capturer) Capture() (*image.RGBA, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.useSHM {
		return c.captureSHM()
	}
	return c.captureGetImage()
}

// CaptureInto fills the caller's destination buffer in one pass. The
// source path (SHM or fallback GetImage) writes directly into dst.Pix
// instead of going through the X11Capturer's internal double-buffer,
// saving one full-frame memcpy per capture.
func (c *X11Capturer) CaptureInto(dst *image.RGBA) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if dst.Rect.Dx() != c.w || dst.Rect.Dy() != c.h {
		return fmt.Errorf("dst size mismatch: dst=%dx%d capturer=%dx%d",
			dst.Rect.Dx(), dst.Rect.Dy(), c.w, c.h)
	}
	if c.useSHM {
		return c.captureSHMInto(dst)
	}
	return c.captureGetImageInto(dst)
}

func (c *X11Capturer) captureGetImageInto(dst *image.RGBA) error {
	cookie := xproto.GetImage(c.conn, xproto.ImageFormatZPixmap,
		xproto.Drawable(c.screen.Root),
		0, 0, uint16(c.w), uint16(c.h), 0xFFFFFFFF)
	reply, err := cookie.Reply()
	if err != nil {
		return fmt.Errorf("GetImage: %w", err)
	}
	n := c.w * c.h * 4
	if len(reply.Data) < n {
		return fmt.Errorf("GetImage returned %d bytes, expected %d", len(reply.Data), n)
	}
	swizzleBGRAtoRGBA(dst.Pix, reply.Data)
	return nil
}

// captureSHM is implemented in capture_x11_shm_linux.go.

func (c *X11Capturer) captureGetImage() (*image.RGBA, error) {
	cookie := xproto.GetImage(c.conn, xproto.ImageFormatZPixmap,
		xproto.Drawable(c.screen.Root),
		0, 0, uint16(c.w), uint16(c.h), 0xFFFFFFFF)

	reply, err := cookie.Reply()
	if err != nil {
		return nil, fmt.Errorf("GetImage: %w", err)
	}

	data := reply.Data
	n := c.w * c.h * 4
	if len(data) < n {
		return nil, fmt.Errorf("GetImage returned %d bytes, expected %d", len(data), n)
	}

	img := c.nextBuffer()
	swizzleBGRAtoRGBA(img.Pix, data)
	return img, nil
}

// nextBuffer returns the *image.RGBA the next capture should fill, advancing
// the double-buffer index. Reallocates on geometry change.
func (c *X11Capturer) nextBuffer() *image.RGBA {
	c.cur ^= 1
	b := c.bufs[c.cur]
	if b == nil || b.Rect.Dx() != c.w || b.Rect.Dy() != c.h {
		b = image.NewRGBA(image.Rect(0, 0, c.w, c.h))
		c.bufs[c.cur] = b
	}
	return b
}

// Close releases X11 resources.
func (c *X11Capturer) Close() {
	c.closeSHM()
	c.conn.Close()
}

// closeSHM is implemented in capture_x11_shm_linux.go.

// X11Poller wraps X11Capturer with a staleness-cached on-demand Capture:
// sessions drive captures themselves through the encoder goroutine, so we
// don't need a background ticker. The last result is cached for a short
// window so concurrent sessions coalesce into one capture.
//
// The capturer is allocated lazily on first use and released when all
// clients disconnect, so an idle peer holds no X connection or SHM segment.
type X11Poller struct {
	mu sync.Mutex

	capturer *X11Capturer
	w, h     int
	// closed at Close so callers can stop waiting on retry backoff.
	done chan struct{}

	// lastFrame/lastAt implement a small cache: multiple near-simultaneous
	// Capture calls (multi-client, or input-coalesced) return the same
	// frame instead of hammering the X server.
	lastFrame *image.RGBA
	lastAt    time.Time

	// initBackoffUntil throttles capturer re-init when the X server is
	// unavailable or flapping.
	initBackoffUntil time.Time

	clients atomic.Int32
	display string
	// cookieHex authenticates the X11 connection; empty falls back to XAUTHORITY env.
	cookieHex string
}

// initRetryBackoff gates capturer re-init attempts after a failure so we
// don't spin on X server errors.
const initRetryBackoff = 2 * time.Second

// NewX11Poller creates a lazy on-demand capturer for the given X display.
// Empty cookieHex falls back to XAUTHORITY env lookup.
func NewX11Poller(display, cookieHex string) *X11Poller {
	return &X11Poller{
		display:   display,
		cookieHex: cookieHex,
		done:      make(chan struct{}),
	}
}

// ClientConnect increments the active client count. The first client triggers
// eager capturer initialisation so that the first FBUpdateRequest doesn't
// pay the X11 connect + SHM attach latency.
func (p *X11Poller) ClientConnect() {
	if p.clients.Add(1) == 1 {
		p.mu.Lock()
		_ = p.ensureCapturerLocked()
		p.mu.Unlock()
	}
}

// ClientDisconnect decrements the active client count. On the last
// disconnect we close the underlying capturer so idle peers cost nothing.
func (p *X11Poller) ClientDisconnect() {
	if p.clients.Add(-1) == 0 {
		p.mu.Lock()
		if p.capturer != nil {
			p.capturer.Close()
			p.capturer = nil
			p.lastFrame = nil
		}
		p.mu.Unlock()
	}
}

// Close releases all resources. Subsequent Capture calls will fail.
func (p *X11Poller) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.done:
	default:
		close(p.done)
	}
	if p.capturer != nil {
		p.capturer.Close()
		p.capturer = nil
	}
}

// Width returns the screen width. Triggers lazy init if needed.
func (p *X11Poller) Width() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.ensureCapturerLocked()
	return p.w
}

// Height returns the screen height. Triggers lazy init if needed.
func (p *X11Poller) Height() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.ensureCapturerLocked()
	return p.h
}

// Cursor satisfies cursorSource by forwarding to the lazily-initialised
// X11Capturer. Asking for the cursor on an idle poller triggers the same
// lazy X11 connection setup as a capture would.
func (p *X11Poller) Cursor() (*image.RGBA, int, int, uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureCapturerLocked(); err != nil {
		return nil, 0, 0, 0, err
	}
	return p.capturer.Cursor()
}

// CursorPos satisfies cursorPositionSource by forwarding to the X11Capturer.
func (p *X11Poller) CursorPos() (int, int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureCapturerLocked(); err != nil {
		return 0, 0, err
	}
	return p.capturer.CursorPos()
}

// Capture returns a fresh frame, serving from the short-lived cache if a
// previous caller captured within freshWindow.
func (p *X11Poller) Capture() (*image.RGBA, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.lastFrame != nil && time.Since(p.lastAt) < freshWindow {
		return p.lastFrame, nil
	}
	if err := p.ensureCapturerLocked(); err != nil {
		return nil, err
	}
	img, err := p.capturer.Capture()
	if err != nil {
		// Drop the capturer so the next call re-inits; the X connection may
		// have died (e.g. Xorg restart).
		p.capturer.Close()
		p.capturer = nil
		p.initBackoffUntil = time.Now().Add(initRetryBackoff)
		return nil, fmt.Errorf("x11 capture: %w", err)
	}
	p.lastFrame = img
	p.lastAt = time.Now()
	return img, nil
}

// CaptureInto fills dst directly via the underlying capturer, bypassing
// the freshness cache. The session's prevFrame/curFrame swap means each
// session needs its own buffer anyway, so caching wouldn't help.
func (p *X11Poller) CaptureInto(dst *image.RGBA) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ensureCapturerLocked(); err != nil {
		return err
	}
	if err := p.capturer.CaptureInto(dst); err != nil {
		p.capturer.Close()
		p.capturer = nil
		p.initBackoffUntil = time.Now().Add(initRetryBackoff)
		return fmt.Errorf("x11 capture: %w", err)
	}
	return nil
}

// ensureCapturerLocked initialises the underlying X11Capturer if not
// already open. Caller must hold p.mu.
func (p *X11Poller) ensureCapturerLocked() error {
	if p.capturer != nil {
		return nil
	}
	select {
	case <-p.done:
		return fmt.Errorf("x11 capturer closed")
	default:
	}
	if time.Now().Before(p.initBackoffUntil) {
		return fmt.Errorf("x11 capturer unavailable (retry scheduled)")
	}
	c, err := NewX11Capturer(p.display, p.cookieHex)
	if err != nil {
		p.initBackoffUntil = time.Now().Add(initRetryBackoff)
		log.Debugf("X11 capturer: %v", err)
		return err
	}
	p.capturer = c
	p.w, p.h = c.Width(), c.Height()
	return nil
}
