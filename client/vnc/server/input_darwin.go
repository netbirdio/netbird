//go:build darwin && !ios

package server

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/ebitengine/purego"
	log "github.com/sirupsen/logrus"
)

// Core Graphics event constants.
const (
	kCGEventSourceStateCombinedSessionState int32 = 0

	kCGEventLeftMouseDown     int32 = 1
	kCGEventLeftMouseUp       int32 = 2
	kCGEventRightMouseDown    int32 = 3
	kCGEventRightMouseUp      int32 = 4
	kCGEventMouseMoved        int32 = 5
	kCGEventLeftMouseDragged  int32 = 6
	kCGEventRightMouseDragged int32 = 7
	kCGEventKeyDown           int32 = 10
	kCGEventKeyUp             int32 = 11
	kCGEventOtherMouseDown    int32 = 25
	kCGEventOtherMouseUp      int32 = 26

	kCGMouseButtonLeft   int32 = 0
	kCGMouseButtonRight  int32 = 1
	kCGMouseButtonCenter int32 = 2

	kCGHIDEventTap int32 = 0

	// IOKit power management constants.
	kIOPMUserActiveLocal  int32  = 0
	kIOPMAssertionLevelOn uint32 = 255
	kCFStringEncodingUTF8 uint32 = 0x08000100
)

var darwinInputOnce sync.Once

var (
	cgEventSourceCreate        func(int32) uintptr
	cgEventCreateKeyboardEvent func(uintptr, uint16, bool) uintptr
	// CGEventCreateMouseEvent takes CGPoint as two separate float64 args.
	// purego can't handle array/struct types but individual float64s work.
	cgEventCreateMouseEvent func(uintptr, int32, float64, float64, int32) uintptr
	cgEventPost             func(int32, uintptr)

	// CGEventCreateScrollWheelEvent is variadic, call via SyscallN.
	cgEventCreateScrollWheelEventAddr uintptr

	axIsProcessTrusted func() bool

	// IOKit power-management bindings used to wake the display and inhibit
	// idle sleep while a VNC client is driving input.
	iopmAssertionDeclareUserActivity func(uintptr, int32, *uint32) int32
	iopmAssertionCreateWithName      func(uintptr, uint32, uintptr, *uint32) int32
	iopmAssertionRelease             func(uint32) int32
	cfStringCreateWithCString        func(uintptr, string, uint32) uintptr

	// Cached CFStrings for assertion name and idle-sleep type.
	pmAssertionNameCFStr      uintptr
	pmPreventIdleDisplayCFStr uintptr

	// Assertion IDs. userActivityID is reused across input events so repeated
	// calls refresh the same assertion rather than create new ones.
	pmMu             sync.Mutex
	userActivityID   uint32
	preventSleepID   uint32
	preventSleepHeld bool
	preventSleepRef  int // refcount across concurrent injectors/sessions

	darwinInputReady  bool
	darwinEventSource uintptr
)

func initDarwinInput() {
	darwinInputOnce.Do(func() {
		cg, err := purego.Dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			log.Debugf("load CoreGraphics for input: %v", err)
			return
		}

		purego.RegisterLibFunc(&cgEventSourceCreate, cg, "CGEventSourceCreate")
		purego.RegisterLibFunc(&cgEventCreateKeyboardEvent, cg, "CGEventCreateKeyboardEvent")
		purego.RegisterLibFunc(&cgEventCreateMouseEvent, cg, "CGEventCreateMouseEvent")
		purego.RegisterLibFunc(&cgEventPost, cg, "CGEventPost")

		sym, err := purego.Dlsym(cg, "CGEventCreateScrollWheelEvent")
		if err == nil {
			cgEventCreateScrollWheelEventAddr = sym
		}

		if ax, err := purego.Dlopen("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices", purego.RTLD_NOW|purego.RTLD_GLOBAL); err == nil {
			if sym, err := purego.Dlsym(ax, "AXIsProcessTrusted"); err == nil {
				purego.RegisterFunc(&axIsProcessTrusted, sym)
			}
		}

		initPowerAssertions()

		darwinInputReady = true
	})
}

func initPowerAssertions() {
	iokit, err := purego.Dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		log.Debugf("load IOKit: %v", err)
		return
	}
	cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		log.Debugf("load CoreFoundation for power assertions: %v", err)
		return
	}

	purego.RegisterLibFunc(&cfStringCreateWithCString, cf, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&iopmAssertionDeclareUserActivity, iokit, "IOPMAssertionDeclareUserActivity")
	purego.RegisterLibFunc(&iopmAssertionCreateWithName, iokit, "IOPMAssertionCreateWithName")
	purego.RegisterLibFunc(&iopmAssertionRelease, iokit, "IOPMAssertionRelease")

	pmAssertionNameCFStr = cfStringCreateWithCString(0, "NetBird VNC input", kCFStringEncodingUTF8)
	pmPreventIdleDisplayCFStr = cfStringCreateWithCString(0, "PreventUserIdleDisplaySleep", kCFStringEncodingUTF8)
}

// wakeDisplay declares user activity so macOS treats the synthesized input as
// real HID activity, waking the display if it is asleep. Called on every key
// and pointer event; the kernel coalesces repeated calls cheaply.
func wakeDisplay() {
	if iopmAssertionDeclareUserActivity == nil || pmAssertionNameCFStr == 0 {
		return
	}
	pmMu.Lock()
	defer pmMu.Unlock()
	id := userActivityID
	r := iopmAssertionDeclareUserActivity(pmAssertionNameCFStr, kIOPMUserActiveLocal, &id)
	if r != 0 {
		log.Tracef("IOPMAssertionDeclareUserActivity returned %d", r)
		return
	}
	userActivityID = id
}

// holdPreventIdleSleep creates an assertion that keeps the display from going
// idle-to-sleep while a VNC session is active. Reference-counted so multiple
// concurrent sessions don't yank the assertion when one of them releases.
func holdPreventIdleSleep() {
	if iopmAssertionCreateWithName == nil || pmPreventIdleDisplayCFStr == 0 || pmAssertionNameCFStr == 0 {
		return
	}
	pmMu.Lock()
	defer pmMu.Unlock()
	preventSleepRef++
	if preventSleepRef > 1 {
		return
	}
	var id uint32
	r := iopmAssertionCreateWithName(pmPreventIdleDisplayCFStr, kIOPMAssertionLevelOn, pmAssertionNameCFStr, &id)
	if r != 0 {
		log.Debugf("IOPMAssertionCreateWithName returned %d", r)
		// Reset the refcount on failure so a later successful hold can take it.
		preventSleepRef = 0
		return
	}
	preventSleepID = id
	preventSleepHeld = true
}

// releasePreventIdleSleep decrements the assertion refcount and only drops
// the actual IOKit assertion on the final release.
func releasePreventIdleSleep() {
	if iopmAssertionRelease == nil {
		return
	}
	pmMu.Lock()
	defer pmMu.Unlock()
	if !preventSleepHeld || preventSleepRef == 0 {
		return
	}
	preventSleepRef--
	if preventSleepRef > 0 {
		return
	}
	if r := iopmAssertionRelease(preventSleepID); r != 0 {
		log.Debugf("IOPMAssertionRelease returned %d", r)
	}
	preventSleepHeld = false
	preventSleepID = 0
}

func ensureEventSource() uintptr {
	if darwinEventSource != 0 {
		return darwinEventSource
	}
	darwinEventSource = cgEventSourceCreate(kCGEventSourceStateCombinedSessionState)
	return darwinEventSource
}

// MacInputInjector injects keyboard and mouse events via Core Graphics.
type MacInputInjector struct {
	lastButtons uint8
	pbcopyPath  string
	pbpastePath string
}

// NewMacInputInjector creates a macOS input injector.
func NewMacInputInjector() (*MacInputInjector, error) {
	initDarwinInput()
	if !darwinInputReady {
		return nil, fmt.Errorf("CoreGraphics not available for input injection")
	}
	checkMacPermissions()

	m := &MacInputInjector{}
	if path, err := exec.LookPath("pbcopy"); err == nil {
		m.pbcopyPath = path
	}
	if path, err := exec.LookPath("pbpaste"); err == nil {
		m.pbpastePath = path
	}
	if m.pbcopyPath == "" || m.pbpastePath == "" {
		log.Debugf("clipboard tools not found (pbcopy=%q, pbpaste=%q)", m.pbcopyPath, m.pbpastePath)
	}

	holdPreventIdleSleep()

	log.Info("macOS input injector ready")
	return m, nil
}

// checkMacPermissions warns and opens the Privacy pane if Accessibility is
// missing. Uses AXIsProcessTrusted which returns immediately; the previous
// osascript probe blocked for 120s (AppleEvent timeout) when access was
// denied, which delayed VNC server startup past client deadlines.
func checkMacPermissions() {
	if axIsProcessTrusted != nil && !axIsProcessTrusted() {
		openPrivacyPane("Privacy_Accessibility")
		log.Warn("Accessibility permission not granted. Input injection will not work. " +
			"Opened System Settings > Privacy & Security > Accessibility; enable netbird.")
	}

	log.Info("Screen Recording permission is required for screen capture. " +
		"If the screen appears black, grant in System Settings > Privacy & Security > Screen Recording.")
}

// openPrivacyPane opens the given Privacy pane in System Settings so the user
// can toggle the permission without navigating manually.
func openPrivacyPane(pane string) {
	url := "x-apple.systempreferences:com.apple.preference.security?" + pane
	if err := exec.Command("open", url).Start(); err != nil {
		log.Debugf("open privacy pane %s: %v", pane, err)
	}
}

// InjectKey simulates a key press or release.
func (m *MacInputInjector) InjectKey(keysym uint32, down bool) {
	wakeDisplay()
	src := ensureEventSource()
	if src == 0 {
		return
	}
	keycode := keysymToMacKeycode(keysym)
	if keycode == 0xFFFF {
		return
	}
	event := cgEventCreateKeyboardEvent(src, keycode, down)
	if event == 0 {
		return
	}
	cgEventPost(kCGHIDEventTap, event)
	cfRelease(event)
}

// InjectPointer simulates mouse movement and button events.
func (m *MacInputInjector) InjectPointer(buttonMask uint8, px, py, serverW, serverH int) {
	wakeDisplay()
	if serverW == 0 || serverH == 0 {
		return
	}
	src := ensureEventSource()
	if src == 0 {
		return
	}
	x, y := scalePxToLogical(px, py, serverW, serverH)
	m.dispatchPointer(src, buttonMask, x, y)
	m.lastButtons = buttonMask
}

// scalePxToLogical converts framebuffer coordinates (physical pixels) into
// the logical points CGEventCreateMouseEvent expects. Falls back to a 1:1
// mapping if the display API is unavailable.
func scalePxToLogical(px, py, serverW, serverH int) (float64, float64) {
	x, y := float64(px), float64(py)
	if cgDisplayPixelsWide == nil || cgMainDisplayID == nil {
		return x, y
	}
	displayID := cgMainDisplayID()
	logicalW := int(cgDisplayPixelsWide(displayID))
	logicalH := int(cgDisplayPixelsHigh(displayID))
	if logicalW <= 0 || logicalH <= 0 {
		return x, y
	}
	return float64(px) * float64(logicalW) / float64(serverW),
		float64(py) * float64(logicalH) / float64(serverH)
}

func (m *MacInputInjector) dispatchPointer(src uintptr, buttonMask uint8, x, y float64) {
	leftDown := buttonMask&0x01 != 0
	rightDown := buttonMask&0x04 != 0
	middleDown := buttonMask&0x02 != 0
	m.postMoveOrDrag(src, leftDown, rightDown, x, y)
	m.postButtonTransitions(src, buttonMask, x, y)
	m.postScrollWheel(src, buttonMask)
	_ = middleDown
}

func (m *MacInputInjector) postMoveOrDrag(src uintptr, leftDown, rightDown bool, x, y float64) {
	switch {
	case leftDown:
		m.postMouse(src, kCGEventLeftMouseDragged, x, y, kCGMouseButtonLeft)
	case rightDown:
		m.postMouse(src, kCGEventRightMouseDragged, x, y, kCGMouseButtonRight)
	default:
		m.postMouse(src, kCGEventMouseMoved, x, y, kCGMouseButtonLeft)
	}
}

// postButtonTransitions emits the up/down events for each button whose state
// changed against m.lastButtons.
func (m *MacInputInjector) postButtonTransitions(src uintptr, buttonMask uint8, x, y float64) {
	emit := func(curBit, prevBit uint8, down, up int32, button int32) {
		cur := buttonMask&curBit != 0
		prev := m.lastButtons&prevBit != 0
		if cur && !prev {
			m.postMouse(src, down, x, y, button)
		} else if !cur && prev {
			m.postMouse(src, up, x, y, button)
		}
	}
	emit(0x01, 0x01, kCGEventLeftMouseDown, kCGEventLeftMouseUp, kCGMouseButtonLeft)
	emit(0x04, 0x04, kCGEventRightMouseDown, kCGEventRightMouseUp, kCGMouseButtonRight)
	emit(0x02, 0x02, kCGEventOtherMouseDown, kCGEventOtherMouseUp, kCGMouseButtonCenter)
}

func (m *MacInputInjector) postScrollWheel(src uintptr, buttonMask uint8) {
	if buttonMask&0x08 != 0 {
		m.postScroll(src, 3)
	}
	if buttonMask&0x10 != 0 {
		m.postScroll(src, -3)
	}
}

func (m *MacInputInjector) postMouse(src uintptr, eventType int32, x, y float64, button int32) {
	if cgEventCreateMouseEvent == nil {
		return
	}
	event := cgEventCreateMouseEvent(src, eventType, x, y, button)
	if event == 0 {
		return
	}
	cgEventPost(kCGHIDEventTap, event)
	cfRelease(event)
}

func (m *MacInputInjector) postScroll(src uintptr, deltaY int32) {
	if cgEventCreateScrollWheelEventAddr == 0 {
		return
	}
	// CGEventCreateScrollWheelEvent(source, units, wheelCount, wheel1delta)
	// units=0 (pixel), wheelCount=1, wheel1delta=deltaY
	// Variadic C function: pass args as uintptr via SyscallN.
	r1, _, _ := purego.SyscallN(cgEventCreateScrollWheelEventAddr,
		src, 0, 1, uintptr(uint32(deltaY)))
	if r1 == 0 {
		return
	}
	cgEventPost(kCGHIDEventTap, r1)
	cfRelease(r1)
}

// SetClipboard sets the macOS clipboard using pbcopy.
func (m *MacInputInjector) SetClipboard(text string) {
	if m.pbcopyPath == "" {
		return
	}
	cmd := exec.Command(m.pbcopyPath)
	cmd.Stdin = strings.NewReader(text)
	if err := cmd.Run(); err != nil {
		log.Tracef("set clipboard via pbcopy: %v", err)
	}
}

// TypeText synthesizes the given text as keystrokes via Core Graphics.
// Used by the dashboard's Paste button so the host clipboard reaches
// the focused remote app even when the app doesn't honor pbpaste-style
// clipboard sync (e.g. login screens, locked-down apps). ASCII printable
// runes only; others are skipped.
func (m *MacInputInjector) TypeText(text string) {
	wakeDisplay()
	src := ensureEventSource()
	if src == 0 {
		return
	}
	const maxChars = 4096
	count := 0
	for _, r := range text {
		if count >= maxChars {
			break
		}
		count++
		typeRune(src, r)
	}
}

// typeRune emits the press/release events for a single ASCII rune, framing
// the keystroke with Shift-down/up when required by the keysym.
func typeRune(src uintptr, r rune) {
	const shiftKey = uint16(0x38) // kVK_Shift
	keysym, shift, ok := keysymForASCIIRune(r)
	if !ok {
		return
	}
	keycode := keysymToMacKeycode(keysym)
	if keycode == 0xFFFF {
		return
	}
	if shift {
		postKey(src, shiftKey, true)
	}
	postKey(src, keycode, true)
	postKey(src, keycode, false)
	if shift {
		postKey(src, shiftKey, false)
	}
}

func postKey(src uintptr, keycode uint16, down bool) {
	e := cgEventCreateKeyboardEvent(src, keycode, down)
	if e == 0 {
		return
	}
	cgEventPost(kCGHIDEventTap, e)
	cfRelease(e)
}

// GetClipboard reads the macOS clipboard using pbpaste.
func (m *MacInputInjector) GetClipboard() string {
	if m.pbpastePath == "" {
		return ""
	}
	out, err := exec.Command(m.pbpastePath).Output()
	if err != nil {
		log.Tracef("get clipboard via pbpaste: %v", err)
		return ""
	}
	return string(out)
}

// Close releases the idle-sleep assertion held for the injector's lifetime.
func (m *MacInputInjector) Close() {
	releasePreventIdleSleep()
}

func keysymToMacKeycode(keysym uint32) uint16 {
	if keysym >= 0x61 && keysym <= 0x7a {
		return asciiToMacKey[keysym-0x61]
	}
	if keysym >= 0x41 && keysym <= 0x5a {
		return asciiToMacKey[keysym-0x41]
	}
	if keysym >= 0x30 && keysym <= 0x39 {
		return digitToMacKey[keysym-0x30]
	}
	if code, ok := specialKeyMap[keysym]; ok {
		return code
	}
	return 0xFFFF
}

var asciiToMacKey = [26]uint16{
	0x00, 0x0B, 0x08, 0x02, 0x0E, 0x03, 0x05, 0x04,
	0x22, 0x26, 0x28, 0x25, 0x2E, 0x2D, 0x1F, 0x23,
	0x0C, 0x0F, 0x01, 0x11, 0x20, 0x09, 0x0D, 0x07,
	0x10, 0x06,
}

var digitToMacKey = [10]uint16{
	0x1D, 0x12, 0x13, 0x14, 0x15, 0x17, 0x16, 0x1A, 0x1C, 0x19,
}

var specialKeyMap = map[uint32]uint16{
	// Whitespace and editing
	0x0020: 0x31, // space
	0xff08: 0x33, // BackSpace
	0xff09: 0x30, // Tab
	0xff0d: 0x24, // Return
	0xff1b: 0x35, // Escape
	0xffff: 0x75, // Delete (forward)

	// Navigation
	0xff50: 0x73, // Home
	0xff51: 0x7B, // Left
	0xff52: 0x7E, // Up
	0xff53: 0x7C, // Right
	0xff54: 0x7D, // Down
	0xff55: 0x74, // Page_Up
	0xff56: 0x79, // Page_Down
	0xff57: 0x77, // End
	0xff63: 0x72, // Insert (Help on Mac)

	// Modifiers
	0xffe1: 0x38, // Shift_L
	0xffe2: 0x3C, // Shift_R
	0xffe3: 0x3B, // Control_L
	0xffe4: 0x3E, // Control_R
	0xffe5: 0x39, // Caps_Lock
	0xffe9: 0x3A, // Alt_L (Option)
	0xffea: 0x3D, // Alt_R (Option)
	0xffe7: 0x37, // Meta_L (Command)
	0xffe8: 0x36, // Meta_R (Command)
	0xffeb: 0x37, // Super_L (Command) - noVNC sends this
	0xffec: 0x36, // Super_R (Command)

	// Mode_switch / ISO_Level3_Shift (sent by noVNC for macOS Option remap)
	0xff7e: 0x3A, // Mode_switch -> Option
	0xfe03: 0x3D, // ISO_Level3_Shift -> Right Option

	// Function keys
	0xffbe: 0x7A, // F1
	0xffbf: 0x78, // F2
	0xffc0: 0x63, // F3
	0xffc1: 0x76, // F4
	0xffc2: 0x60, // F5
	0xffc3: 0x61, // F6
	0xffc4: 0x62, // F7
	0xffc5: 0x64, // F8
	0xffc6: 0x65, // F9
	0xffc7: 0x6D, // F10
	0xffc8: 0x67, // F11
	0xffc9: 0x6F, // F12
	0xffca: 0x69, // F13
	0xffcb: 0x6B, // F14
	0xffcc: 0x71, // F15
	0xffcd: 0x6A, // F16
	0xffce: 0x40, // F17
	0xffcf: 0x4F, // F18
	0xffd0: 0x50, // F19
	0xffd1: 0x5A, // F20

	// Punctuation (US keyboard layout, keysym = ASCII code)
	0x002d: 0x1B, // minus -
	0x003d: 0x18, // equal =
	0x005b: 0x21, // bracketleft [
	0x005d: 0x1E, // bracketright ]
	0x005c: 0x2A, // backslash
	0x003b: 0x29, // semicolon ;
	0x0027: 0x27, // apostrophe '
	0x0060: 0x32, // grave `
	0x002c: 0x2B, // comma ,
	0x002e: 0x2F, // period .
	0x002f: 0x2C, // slash /

	// Shifted punctuation (noVNC sends these as separate keysyms)
	0x005f: 0x1B, // underscore _ (shift+minus)
	0x002b: 0x18, // plus + (shift+equal)
	0x007b: 0x21, // braceleft { (shift+[)
	0x007d: 0x1E, // braceright } (shift+])
	0x007c: 0x2A, // bar | (shift+\)
	0x003a: 0x29, // colon : (shift+;)
	0x0022: 0x27, // quotedbl " (shift+')
	0x007e: 0x32, // tilde ~ (shift+`)
	0x003c: 0x2B, // less < (shift+,)
	0x003e: 0x2F, // greater > (shift+.)
	0x003f: 0x2C, // question ? (shift+/)
	0x0021: 0x12, // exclam ! (shift+1)
	0x0040: 0x13, // at @ (shift+2)
	0x0023: 0x14, // numbersign # (shift+3)
	0x0024: 0x15, // dollar $ (shift+4)
	0x0025: 0x17, // percent % (shift+5)
	0x005e: 0x16, // asciicircum ^ (shift+6)
	0x0026: 0x1A, // ampersand & (shift+7)
	0x002a: 0x1C, // asterisk * (shift+8)
	0x0028: 0x19, // parenleft ( (shift+9)
	0x0029: 0x1D, // parenright ) (shift+0)

	// Numpad
	0xffb0: 0x52, // KP_0
	0xffb1: 0x53, // KP_1
	0xffb2: 0x54, // KP_2
	0xffb3: 0x55, // KP_3
	0xffb4: 0x56, // KP_4
	0xffb5: 0x57, // KP_5
	0xffb6: 0x58, // KP_6
	0xffb7: 0x59, // KP_7
	0xffb8: 0x5B, // KP_8
	0xffb9: 0x5C, // KP_9
	0xffae: 0x41, // KP_Decimal
	0xffaa: 0x43, // KP_Multiply
	0xffab: 0x45, // KP_Add
	0xffad: 0x4E, // KP_Subtract
	0xffaf: 0x4B, // KP_Divide
	0xff8d: 0x4C, // KP_Enter
	0xffbd: 0x51, // KP_Equal
}

var _ InputInjector = (*MacInputInjector)(nil)
