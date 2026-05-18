//go:build windows

package server

import (
	"runtime"
	"sync"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	procOpenEventW = kernel32.NewProc("OpenEventW")
	procSendInput  = user32.NewProc("SendInput")
	procVkKeyScanA = user32.NewProc("VkKeyScanA")
)

const eventModifyState = 0x0002

const (
	inputMouse    = 0
	inputKeyboard = 1

	mouseeventfMove       = 0x0001
	mouseeventfLeftDown   = 0x0002
	mouseeventfLeftUp     = 0x0004
	mouseeventfRightDown  = 0x0008
	mouseeventfRightUp    = 0x0010
	mouseeventfMiddleDown = 0x0020
	mouseeventfMiddleUp   = 0x0040
	mouseeventfWheel      = 0x0800
	mouseeventfAbsolute   = 0x8000

	wheelDelta = 120

	keyeventfExtendedKey = 0x0001
	keyeventfKeyUp       = 0x0002
	keyeventfUnicode     = 0x0004
	keyeventfScanCode    = 0x0008
)


// maxTypedClipboardChars caps the number of characters we will synthesize as
// keystrokes when falling back on the Winlogon desktop. Passwords are short;
// a huge clipboard getting typed into the login screen would be surprising.
const maxTypedClipboardChars = 4096

type mouseInput struct {
	Dx          int32
	Dy          int32
	MouseData   uint32
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
}

type keybdInput struct {
	WVk         uint16
	WScan       uint16
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
	_           [8]byte
}

type inputUnion [32]byte

type winInput struct {
	Type uint32
	_    [4]byte
	Data inputUnion
}

func sendMouseInput(flags uint32, dx, dy int32, mouseData uint32) {
	mi := mouseInput{
		Dx:        dx,
		Dy:        dy,
		MouseData: mouseData,
		DwFlags:   flags,
	}
	inp := winInput{Type: inputMouse}
	copy(inp.Data[:], (*[unsafe.Sizeof(mi)]byte)(unsafe.Pointer(&mi))[:])
	r, _, err := procSendInput.Call(1, uintptr(unsafe.Pointer(&inp)), unsafe.Sizeof(inp))
	if r == 0 {
		log.Tracef("SendInput(mouse flags=0x%x): %v", flags, err)
	}
}

func sendKeyInput(vk uint16, scanCode uint16, flags uint32) {
	ki := keybdInput{
		WVk:     vk,
		WScan:   scanCode,
		DwFlags: flags,
	}
	inp := winInput{Type: inputKeyboard}
	copy(inp.Data[:], (*[unsafe.Sizeof(ki)]byte)(unsafe.Pointer(&ki))[:])
	r, _, err := procSendInput.Call(1, uintptr(unsafe.Pointer(&inp)), unsafe.Sizeof(inp))
	if r == 0 {
		log.Tracef("SendInput(key vk=0x%x): %v", vk, err)
	}
}

const sasEventName = `Global\NetBirdVNC_SAS`

type inputCmd struct {
	isKey       bool
	isScancode  bool
	isClipboard bool
	isType      bool
	keysym      uint32
	scancode    uint32
	down        bool
	buttonMask  uint8
	x, y        int
	serverW     int
	serverH     int
	clipText    string
}

// WindowsInputInjector delivers input events from a dedicated OS thread that
// calls switchToInputDesktop before each injection. SendInput targets the
// calling thread's desktop, so the injection thread must be on the same
// desktop the user sees.
type WindowsInputInjector struct {
	ch             chan inputCmd
	closed         chan struct{}
	closeOnce      sync.Once
	prevButtonMask uint8
	ctrlDown       bool
	altDown        bool
}

// NewWindowsInputInjector creates a desktop-aware input injector.
func NewWindowsInputInjector() *WindowsInputInjector {
	w := &WindowsInputInjector{
		ch:     make(chan inputCmd, 64),
		closed: make(chan struct{}),
	}
	go w.loop()
	return w
}

// Close stops the injector loop. Safe to call multiple times. Subsequent
// Inject*/SetClipboard/TypeText calls become no-ops; we use a separate
// signal channel rather than closing ch so late senders can't panic.
func (w *WindowsInputInjector) Close() {
	w.closeOnce.Do(func() {
		close(w.closed)
	})
}

// tryEnqueue posts a command unless the injector is closed or the channel is
// full. Non-blocking so callers (RFB read loop) never stall.
func (w *WindowsInputInjector) tryEnqueue(cmd inputCmd) {
	select {
	case <-w.closed:
		return
	default:
	}
	select {
	case w.ch <- cmd:
	default:
	}
}

func (w *WindowsInputInjector) loop() {
	runtime.LockOSThread()

	for {
		select {
		case <-w.closed:
			return
		case cmd := <-w.ch:
			w.dispatch(cmd)
		}
	}
}

func (w *WindowsInputInjector) dispatch(cmd inputCmd) {
	// Switch to the current input desktop so SendInput and the clipboard
	// API target the desktop the user sees. The returned name tells us
	// whether we are on the secure Winlogon desktop.
	_, _ = switchToInputDesktop()

	switch {
	case cmd.isClipboard:
		w.doSetClipboard(cmd.clipText)
	case cmd.isType:
		w.typeUnicodeText(cmd.clipText)
	case cmd.isScancode:
		w.doInjectKeyScancode(cmd.scancode, cmd.keysym, cmd.down)
	case cmd.isKey:
		w.doInjectKey(cmd.keysym, cmd.down)
	default:
		w.doInjectPointer(cmd.buttonMask, cmd.x, cmd.y, cmd.serverW, cmd.serverH)
	}
}

// InjectKey queues a key event for injection on the input desktop thread.
func (w *WindowsInputInjector) InjectKey(keysym uint32, down bool) {
	w.tryEnqueue(inputCmd{isKey: true, keysym: keysym, down: down})
}

// InjectKeyScancode queues a raw-scancode key event. PC AT Set 1 maps
// directly onto what SendInput's KEYEVENTF_SCANCODE flag wants, so the
// only translation is splitting the optional 0xE0 prefix off into the
// KEYEVENTF_EXTENDEDKEY flag. keysym is the client-provided fallback we
// reach for if the scancode is zero.
func (w *WindowsInputInjector) InjectKeyScancode(scancode uint32, keysym uint32, down bool) {
	if scancode == 0 {
		w.InjectKey(keysym, down)
		return
	}
	w.tryEnqueue(inputCmd{isScancode: true, scancode: scancode, keysym: keysym, down: down})
}

// InjectPointer queues a pointer event for injection on the input desktop
// thread. Pointer events coalesce: when the channel is full (slow desktop
// switch, hung SendInput), drop the new sample so the read loop never
// blocks. The next mouse event carries fresher position anyway.
func (w *WindowsInputInjector) InjectPointer(buttonMask uint8, x, y, serverW, serverH int) {
	w.tryEnqueue(inputCmd{buttonMask: buttonMask, x: x, y: y, serverW: serverW, serverH: serverH})
}

// doInjectKeyScancode injects a key event using the QEMU scancode directly,
// bypassing the keysym→VK lookup. Windows accepts PC AT Set 1 scancodes
// natively via KEYEVENTF_SCANCODE, so the only work is splitting the
// optional 0xE0 prefix off into the EXTENDEDKEY flag and tracking
// modifier state for the SAS Ctrl+Alt+Del shortcut.
func (w *WindowsInputInjector) doInjectKeyScancode(scancode, keysym uint32, down bool) {
	switch keysym {
	case 0xffe3, 0xffe4:
		w.ctrlDown = down
	case 0xffe9, 0xffea:
		w.altDown = down
	}
	if (keysym == 0xff9f || keysym == 0xffff) && w.ctrlDown && w.altDown && down {
		signalSAS()
		return
	}
	flags := uint32(keyeventfScanCode)
	if !down {
		flags |= keyeventfKeyUp
	}
	if qemuScancodeIsExtended(scancode) {
		flags |= keyeventfExtendedKey
	}
	sendKeyInput(0, qemuScancodeLowByte(scancode), flags)
}

func (w *WindowsInputInjector) doInjectKey(keysym uint32, down bool) {
	switch keysym {
	case 0xffe3, 0xffe4:
		w.ctrlDown = down
	case 0xffe9, 0xffea:
		w.altDown = down
	}

	if (keysym == 0xff9f || keysym == 0xffff) && w.ctrlDown && w.altDown && down {
		signalSAS()
		return
	}

	vk, _, extended := keysym2VK(keysym)
	if vk == 0 {
		return
	}
	var flags uint32
	if !down {
		flags |= keyeventfKeyUp
	}
	if extended {
		flags |= keyeventfExtendedKey
	}
	sendKeyInput(vk, 0, flags)
}

// signalSAS signals the SAS named event. A listener in Session 0
// (startSASListener) calls SendSAS to trigger the Secure Attention Sequence.
func signalSAS() {
	namePtr, err := windows.UTF16PtrFromString(sasEventName)
	if err != nil {
		log.Warnf("SAS UTF16: %v", err)
		return
	}
	h, _, lerr := procOpenEventW.Call(
		uintptr(eventModifyState),
		0,
		uintptr(unsafe.Pointer(namePtr)),
	)
	if h == 0 {
		log.Warnf("OpenEvent(%s): %v", sasEventName, lerr)
		return
	}
	ev := windows.Handle(h)
	defer func() { _ = windows.CloseHandle(ev) }()
	if err := windows.SetEvent(ev); err != nil {
		log.Warnf("SetEvent SAS: %v", err)
	} else {
		log.Info("SAS event signaled")
	}
}

func (w *WindowsInputInjector) doInjectPointer(buttonMask uint8, x, y, serverW, serverH int) {
	if serverW == 0 || serverH == 0 {
		return
	}

	absX := int32(x * 65535 / serverW)
	absY := int32(y * 65535 / serverH)

	sendMouseInput(mouseeventfMove|mouseeventfAbsolute, absX, absY, 0)

	changed := buttonMask ^ w.prevButtonMask
	w.prevButtonMask = buttonMask

	type btnMap struct {
		bit  uint8
		down uint32
		up   uint32
	}
	buttons := [...]btnMap{
		{0x01, mouseeventfLeftDown, mouseeventfLeftUp},
		{0x02, mouseeventfMiddleDown, mouseeventfMiddleUp},
		{0x04, mouseeventfRightDown, mouseeventfRightUp},
	}
	for _, b := range buttons {
		if changed&b.bit == 0 {
			continue
		}
		var flags uint32
		if buttonMask&b.bit != 0 {
			flags = b.down
		} else {
			flags = b.up
		}
		sendMouseInput(flags|mouseeventfAbsolute, absX, absY, 0)
	}

	negWheelDelta := ^uint32(wheelDelta - 1)
	if changed&0x08 != 0 && buttonMask&0x08 != 0 {
		sendMouseInput(mouseeventfWheel|mouseeventfAbsolute, absX, absY, wheelDelta)
	}
	if changed&0x10 != 0 && buttonMask&0x10 != 0 {
		sendMouseInput(mouseeventfWheel|mouseeventfAbsolute, absX, absY, negWheelDelta)
	}
}

// keysym2VK converts an X11 keysym to a Windows virtual key code.
func keysym2VK(keysym uint32) (vk uint16, scan uint16, extended bool) {
	if keysym >= 0x20 && keysym <= 0x7e {
		r, _, _ := procVkKeyScanA.Call(uintptr(keysym))
		vk = uint16(r & 0xff)
		return
	}

	if keysym >= 0xffbe && keysym <= 0xffc9 {
		vk = uint16(0x70 + keysym - 0xffbe)
		return
	}

	switch keysym {
	case 0xff08:
		vk = 0x08 // Backspace
	case 0xff09:
		vk = 0x09 // Tab
	case 0xff0d:
		vk = 0x0d // Return
	case 0xff1b:
		vk = 0x1b // Escape
	case 0xff63:
		vk, extended = 0x2d, true // Insert
	case 0xff9f, 0xffff:
		vk, extended = 0x2e, true // Delete
	case 0xff50:
		vk, extended = 0x24, true // Home
	case 0xff57:
		vk, extended = 0x23, true // End
	case 0xff55:
		vk, extended = 0x21, true // PageUp
	case 0xff56:
		vk, extended = 0x22, true // PageDown
	case 0xff51:
		vk, extended = 0x25, true // Left
	case 0xff52:
		vk, extended = 0x26, true // Up
	case 0xff53:
		vk, extended = 0x27, true // Right
	case 0xff54:
		vk, extended = 0x28, true // Down
	case 0xffe1, 0xffe2:
		vk = 0x10 // Shift
	case 0xffe3, 0xffe4:
		vk = 0x11 // Control
	case 0xffe9, 0xffea:
		vk = 0x12 // Alt
	case 0xffe5:
		vk = 0x14 // CapsLock
	case 0xffe7, 0xffeb:
		vk, extended = 0x5B, true // Meta_L / Super_L -> Left Windows
	case 0xffe8, 0xffec:
		vk, extended = 0x5C, true // Meta_R / Super_R -> Right Windows
	case 0xff61:
		vk = 0x2c // PrintScreen
	case 0xff13:
		vk = 0x13 // Pause
	case 0xff14:
		vk = 0x91 // ScrollLock
	}
	return
}

var (
	procOpenClipboard              = user32.NewProc("OpenClipboard")
	procCloseClipboard             = user32.NewProc("CloseClipboard")
	procEmptyClipboard             = user32.NewProc("EmptyClipboard")
	procSetClipboardData           = user32.NewProc("SetClipboardData")
	procGetClipboardData           = user32.NewProc("GetClipboardData")
	procIsClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")

	procGlobalAlloc  = kernel32.NewProc("GlobalAlloc")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

// SetClipboard queues a request to update the Windows clipboard with the
// given UTF-8 text. The work runs on the input thread so it follows the
// current input desktop. Secure desktops (Winlogon, UAC) have isolated
// clipboards we cannot reach, so the call is a no-op there; use TypeText
// to enter text into a secure desktop instead.
func (w *WindowsInputInjector) SetClipboard(text string) {
	w.tryEnqueue(inputCmd{isClipboard: true, clipText: text})
}

// TypeText queues a request to synthesize the given text as Unicode
// keystrokes on the current input desktop. Targets the secure desktop
// when the user is on Winlogon/UAC, where the clipboard is unreachable.
func (w *WindowsInputInjector) TypeText(text string) {
	w.tryEnqueue(inputCmd{isType: true, clipText: text})
}

func (w *WindowsInputInjector) doSetClipboard(text string) {
	utf16, err := windows.UTF16FromString(text)
	if err != nil {
		log.Tracef("clipboard UTF16 encode: %v", err)
		return
	}

	size := uintptr(len(utf16) * 2)
	hMem, _, _ := procGlobalAlloc.Call(gmemMoveable, size)
	if hMem == 0 {
		log.Tracef("GlobalAlloc for clipboard: allocation returned nil")
		return
	}

	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		log.Tracef("GlobalLock for clipboard: lock returned nil")
		return
	}
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), len(utf16)), utf16)
	_, _, _ = procGlobalUnlock.Call(hMem)

	r, _, lerr := procOpenClipboard.Call(0)
	if r == 0 {
		log.Tracef("OpenClipboard: %v", lerr)
		return
	}
	defer logCleanupCall("CloseClipboard", procCloseClipboard)

	_, _, _ = procEmptyClipboard.Call()
	r, _, lerr = procSetClipboardData.Call(cfUnicodeText, hMem)
	if r == 0 {
		log.Tracef("SetClipboardData: %v", lerr)
	}
}

// typeUnicodeText synthesizes the given text as Unicode keystrokes via
// SendInput+KEYEVENTF_UNICODE. Used on the Winlogon secure desktop where the
// clipboard is isolated: this lets a VNC client paste a password into the
// login or credential prompt by sending ClientCutText.
func (w *WindowsInputInjector) typeUnicodeText(text string) {
	utf16, err := windows.UTF16FromString(text)
	if err != nil {
		log.Tracef("clipboard UTF16 encode: %v", err)
		return
	}
	if len(utf16) > 0 && utf16[len(utf16)-1] == 0 {
		utf16 = utf16[:len(utf16)-1]
	}
	if len(utf16) > maxTypedClipboardChars {
		log.Warnf("clipboard paste on Winlogon truncated to %d chars", maxTypedClipboardChars)
		utf16 = utf16[:maxTypedClipboardChars]
	}
	for _, c := range utf16 {
		sendKeyInput(0, c, keyeventfUnicode)
		sendKeyInput(0, c, keyeventfUnicode|keyeventfKeyUp)
	}
}

// GetClipboard reads the Windows clipboard as UTF-8 text.
func (w *WindowsInputInjector) GetClipboard() string {
	r, _, _ := procIsClipboardFormatAvailable.Call(cfUnicodeText)
	if r == 0 {
		return ""
	}

	r, _, lerr := procOpenClipboard.Call(0)
	if r == 0 {
		log.Tracef("OpenClipboard for read: %v", lerr)
		return ""
	}
	defer logCleanupCall("CloseClipboard", procCloseClipboard)

	hData, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if hData == 0 {
		return ""
	}

	ptr, _, _ := procGlobalLock.Call(hData)
	if ptr == 0 {
		return ""
	}
	defer logCleanupCallArgs("GlobalUnlock", procGlobalUnlock, hData)

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr)))
}

var _ InputInjector = (*WindowsInputInjector)(nil)

var _ ScreenCapturer = (*DesktopCapturer)(nil)
