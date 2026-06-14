//go:build (linux && !android) || freebsd

package server

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"
)

// X11InputInjector injects keyboard and mouse events via the XTest extension.
type X11InputInjector struct {
	conn              *xgb.Conn
	root              xproto.Window
	screen            *xproto.ScreenInfo
	display           string
	keysymMap         map[uint32]byte
	lastButtons       uint16
	clipboardTool     string
	clipboardToolName string
	// authFile points xclip/xsel at the per-session Xauthority via XAUTHORITY env.
	authFile string
}

// NewX11InputInjector connects to the X11 display and initializes XTest.
// Empty cookieHex/authFile fall back to XAUTHORITY env lookup.
func NewX11InputInjector(display, cookieHex, authFile string) (*X11InputInjector, error) {
	detectX11Display()

	if display == "" {
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

	if err := xtest.Init(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("init XTest extension: %w", err)
	}

	setup := xproto.Setup(conn)
	if len(setup.Roots) == 0 {
		conn.Close()
		return nil, fmt.Errorf("no X11 screens")
	}
	screen := setup.Roots[0]

	inj := &X11InputInjector{
		conn:     conn,
		root:     screen.Root,
		screen:   &screen,
		display:  display,
		authFile: authFile,
	}
	inj.cacheKeyboardMapping()
	inj.resolveClipboardTool()

	log.Infof("X11 input injector ready (display=%s)", display)
	return inj, nil
}

// InjectKey simulates a key press or release. keysym is an X11 KeySym.
func (x *X11InputInjector) InjectKey(keysym uint32, down bool) {
	keycode := x.keysymToKeycode(keysym)
	if keycode == 0 {
		return
	}
	x.fakeKeyEvent(keycode, down)
}

// InjectKeyScancode injects using the QEMU scancode by translating to a
// Linux KEY_ code and then to an X11 keycode (KEY_* + xkbKeycodeOffset).
// On a server running a standard XKB keymap this is layout-independent:
// the scancode names the physical key, the server's layout determines the
// resulting character. Falls back to the keysym path when the scancode
// has no Linux mapping.
func (x *X11InputInjector) InjectKeyScancode(scancode, keysym uint32, down bool) {
	linuxKey := qemuScancodeToLinuxKey(scancode)
	if linuxKey == 0 {
		x.InjectKey(keysym, down)
		return
	}
	x.fakeKeyEvent(byte(linuxKey+xkbKeycodeOffset), down)
}

// xkbKeycodeOffset is the per-server constant offset between Linux KEY_*
// event codes and the X server's keycode space under XKB. The X protocol
// reserves keycodes 0..7 for internal use, so any normal XKB keymap
// starts at 8 (KEY_ESC=1 → X keycode 9, KEY_A=30 → X keycode 38, etc.).
const xkbKeycodeOffset = 8

// fakeKeyEvent sends an XTest FakeInput for a press or release.
func (x *X11InputInjector) fakeKeyEvent(keycode byte, down bool) {
	var eventType byte
	if down {
		eventType = xproto.KeyPress
	} else {
		eventType = xproto.KeyRelease
	}
	xtest.FakeInput(x.conn, eventType, keycode, 0, x.root, 0, 0, 0)
}

// InjectPointer simulates mouse movement and button events.
func (x *X11InputInjector) InjectPointer(buttonMask uint16, px, py, serverW, serverH int) {
	if serverW == 0 || serverH == 0 {
		return
	}

	// Scale to actual screen coordinates.
	screenW := int(x.screen.WidthInPixels)
	screenH := int(x.screen.HeightInPixels)
	absX := px * screenW / serverW
	absY := py * screenH / serverH

	// Move pointer.
	xtest.FakeInput(x.conn, xproto.MotionNotify, 0, 0, x.root, int16(absX), int16(absY), 0)

	// Handle button events. RFB button mask: bit0=left, bit1=middle, bit2=right,
	// bit3=scrollUp, bit4=scrollDown. X11 buttons: 1=left, 2=middle, 3=right,
	// 4=scrollUp, 5=scrollDown.
	type btnMap struct {
		rfbBit uint16
		x11Btn byte
	}
	// X11 button numbers: 1=left, 2=middle, 3=right, 4/5=scroll up/down,
	// 6/7=scroll left/right (skipped), 8=back, 9=forward.
	buttons := [...]btnMap{
		{0x01, 1},
		{0x02, 2},
		{0x04, 3},
		{0x08, 4},
		{0x10, 5},
		{1 << 7, 8},
		{1 << 8, 9},
	}

	for _, b := range buttons {
		pressed := buttonMask&b.rfbBit != 0
		wasPressed := x.lastButtons&b.rfbBit != 0
		if b.x11Btn == 4 || b.x11Btn == 5 {
			// Scroll: send press+release on each scroll event.
			if pressed {
				xtest.FakeInput(x.conn, xproto.ButtonPress, b.x11Btn, 0, x.root, 0, 0, 0)
				xtest.FakeInput(x.conn, xproto.ButtonRelease, b.x11Btn, 0, x.root, 0, 0, 0)
			}
		} else {
			if pressed && !wasPressed {
				xtest.FakeInput(x.conn, xproto.ButtonPress, b.x11Btn, 0, x.root, 0, 0, 0)
			} else if !pressed && wasPressed {
				xtest.FakeInput(x.conn, xproto.ButtonRelease, b.x11Btn, 0, x.root, 0, 0, 0)
			}
		}
	}
	x.lastButtons = buttonMask
}

// cacheKeyboardMapping fetches the X11 keyboard mapping once and stores it
// as a keysym-to-keycode map, avoiding a round-trip per keystroke.
func (x *X11InputInjector) cacheKeyboardMapping() {
	setup := xproto.Setup(x.conn)
	minKeycode := setup.MinKeycode
	maxKeycode := setup.MaxKeycode

	reply, err := xproto.GetKeyboardMapping(x.conn, minKeycode,
		byte(maxKeycode-minKeycode+1)).Reply()
	if err != nil {
		log.Debugf("cache keyboard mapping: %v", err)
		x.keysymMap = make(map[uint32]byte)
		return
	}

	m := make(map[uint32]byte, int(maxKeycode-minKeycode+1)*int(reply.KeysymsPerKeycode))
	keysymsPerKeycode := int(reply.KeysymsPerKeycode)
	for i := int(minKeycode); i <= int(maxKeycode); i++ {
		offset := (i - int(minKeycode)) * keysymsPerKeycode
		for j := 0; j < keysymsPerKeycode; j++ {
			ks := uint32(reply.Keysyms[offset+j])
			if ks != 0 {
				if _, exists := m[ks]; !exists {
					m[ks] = byte(i)
				}
			}
		}
	}
	x.keysymMap = m
}

// keysymToKeycode looks up a cached keysym-to-keycode mapping.
// Returns 0 if the keysym is not mapped.
func (x *X11InputInjector) keysymToKeycode(keysym uint32) byte {
	return x.keysymMap[keysym]
}

// SetClipboard sets the X11 clipboard using xclip or xsel.
func (x *X11InputInjector) SetClipboard(text string) {
	if x.clipboardTool == "" {
		return
	}

	var cmd *exec.Cmd
	if x.clipboardToolName == "xclip" {
		cmd = exec.Command(x.clipboardTool, "-selection", "clipboard")
	} else {
		cmd = exec.Command(x.clipboardTool, "--clipboard", "--input")
	}
	cmd.Env = x.clipboardEnv()
	cmd.Stdin = strings.NewReader(text)
	if err := cmd.Run(); err != nil {
		log.Debugf("set clipboard via %s: %v", x.clipboardToolName, err)
	}
}

// TypeText synthesizes the given text as keystrokes via XTest. Used in
// places where the focused application isn't clipboard-aware (e.g. a TTY
// login in an X11 session, an SDDM/GDM password field that ignores
// XSelection, or a kiosk app), so stuffing the X clipboard and relying on
// Ctrl+V would not reach the input.
//
// Limitation: only ASCII printable characters are typed. Non-ASCII runes
// are skipped: a paste workflow for them needs Wayland-aware text input
// or layout introspection that this path does not implement.
func (x *X11InputInjector) TypeText(text string) {
	const maxChars = 4096
	count := 0
	for _, r := range text {
		if count >= maxChars {
			break
		}
		count++
		keysym, shift, ok := keysymForASCIIRune(r)
		if !ok {
			continue
		}
		keycode := x.keysymToKeycode(keysym)
		if keycode == 0 {
			continue
		}
		var shiftCode byte
		if shift {
			shiftCode = x.keysymToKeycode(0xffe1) // Shift_L
			if shiftCode != 0 {
				xtest.FakeInput(x.conn, xproto.KeyPress, shiftCode, 0, x.root, 0, 0, 0)
			}
		}
		xtest.FakeInput(x.conn, xproto.KeyPress, keycode, 0, x.root, 0, 0, 0)
		xtest.FakeInput(x.conn, xproto.KeyRelease, keycode, 0, x.root, 0, 0, 0)
		if shift && shiftCode != 0 {
			xtest.FakeInput(x.conn, xproto.KeyRelease, shiftCode, 0, x.root, 0, 0, 0)
		}
	}
}

func (x *X11InputInjector) resolveClipboardTool() {
	for _, name := range []string{"xclip", "xsel"} {
		path, err := exec.LookPath(name)
		if err == nil {
			x.clipboardTool = path
			x.clipboardToolName = name
			log.Debugf("clipboard tool resolved to %s", path)
			return
		}
	}
	log.Debugf("no clipboard tool (xclip/xsel) found, clipboard sync disabled")
}

// GetClipboard reads the X11 clipboard using xclip or xsel.
func (x *X11InputInjector) GetClipboard() string {
	if x.clipboardTool == "" {
		return ""
	}

	var cmd *exec.Cmd
	if x.clipboardToolName == "xclip" {
		cmd = exec.Command(x.clipboardTool, "-selection", "clipboard", "-o")
	} else {
		cmd = exec.Command(x.clipboardTool, "--clipboard", "--output")
	}
	cmd.Env = x.clipboardEnv()
	out, err := cmd.Output()
	if err != nil {
		// Exit status 1 just means there is no STRING selection set yet,
		// which is the steady state on a fresh Xvfb session, logging it
		// every clipboard poll (2s) floods the trace stream.
		return ""
	}
	return string(out)
}

func (x *X11InputInjector) clipboardEnv() []string {
	env := []string{envDisplay + "=" + x.display}
	switch {
	case x.authFile != "":
		env = append(env, envXAuthority+"="+x.authFile)
	default:
		if auth := os.Getenv(envXAuthority); auth != "" {
			env = append(env, envXAuthority+"="+auth)
		}
	}
	return env
}

// Close releases X11 resources.
func (x *X11InputInjector) Close() {
	x.conn.Close()
}

var _ InputInjector = (*X11InputInjector)(nil)
var _ ScreenCapturer = (*X11Poller)(nil)
