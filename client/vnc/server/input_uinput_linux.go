//go:build linux

package server

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
	"unicode"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// /dev/uinput ioctl numbers. Computed from the kernel _IO/_IOW macros so
// we don't depend on cgo. UINPUT_IOCTL_BASE = 'U' = 0x55.
const (
	uiDevCreate  = 0x5501
	uiDevDestroy = 0x5502
	// _IOW('U', 3, struct uinput_setup); uinput_setup is 92 bytes on amd64.
	uiDevSetup    = (1 << 30) | (92 << 16) | (0x55 << 8) | 3
	uiSetEvBit    = (1 << 30) | (4 << 16) | (0x55 << 8) | 100
	uiSetKeyBit   = (1 << 30) | (4 << 16) | (0x55 << 8) | 101
	uiSetAbsBit   = (1 << 30) | (4 << 16) | (0x55 << 8) | 103
	uinputAbsSize = 64 // legacy struct uses absmin/absmax/absfuzz/absflat[64].
)

// Linux input event types and key codes (linux/input-event-codes.h).
const (
	evSyn = 0x00
	evKey = 0x01
	evAbs = 0x03
	evRep = 0x14

	synReport = 0

	absX = 0x00
	absY = 0x01

	btnLeft   = 0x110
	btnRight  = 0x111
	btnMiddle = 0x112
	btnSide   = 0x113 // mouse-back (X1)
	btnExtra  = 0x114 // mouse-forward (X2)
)

// inputEvent matches struct input_event for x86_64 (timeval is 16 bytes).
// Total size 24 bytes; Go's natural alignment matches the kernel layout.
type inputEvent struct {
	TvSec  int64
	TvUsec int64
	Type   uint16
	Code   uint16
	Value  int32
}

// UInputInjector synthesizes keyboard and mouse events via /dev/uinput.
// Used as a fallback when X11 isn't running, e.g. at the kernel console
// or pre-login screen on a server without X. Requires root or
// CAP_SYS_ADMIN, which the netbird service has.
type UInputInjector struct {
	mu          sync.Mutex
	fd          int
	closeOnce   sync.Once
	keysymToKey map[uint32]uint16
	prevButtons uint16
	screenW     int
	screenH     int
}

// NewUInputInjector opens /dev/uinput and registers a virtual keyboard +
// absolute pointer device sized to (w, h). The dimensions are needed
// because uinput's ABS axes don't autoscale; we always send absolute
// coordinates and let the kernel route them to the right monitor.
func NewUInputInjector(w, h int) (*UInputInjector, error) {
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("invalid screen size: %dx%d", w, h)
	}
	fd, err := unix.Open("/dev/uinput", unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/uinput: %w", err)
	}

	if err := setBit(fd, uiSetEvBit, evKey); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := setBit(fd, uiSetEvBit, evAbs); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := setBit(fd, uiSetEvBit, evSyn); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// Advertise key auto-repeat so the kernel input core repeats held
	// keys at the configured rate (default ~250 ms delay, ~33 ms period).
	// Without this, holding Backspace etc. only deletes one character.
	if err := setBit(fd, uiSetEvBit, evRep); err != nil {
		unix.Close(fd)
		return nil, err
	}

	keymap := buildUInputKeymap()
	for _, key := range keymap {
		if err := setBit(fd, uiSetKeyBit, uint32(key)); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("UI_SET_KEYBIT %d: %w", key, err)
		}
	}
	for _, btn := range []uint16{btnLeft, btnRight, btnMiddle, btnSide, btnExtra} {
		if err := setBit(fd, uiSetKeyBit, uint32(btn)); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("UI_SET_KEYBIT btn %d: %w", btn, err)
		}
	}
	if err := setBit(fd, uiSetAbsBit, absX); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := setBit(fd, uiSetAbsBit, absY); err != nil {
		unix.Close(fd)
		return nil, err
	}

	if err := writeUInputUserDev(fd, w, h); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uiDevCreate, 0); e != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("UI_DEV_CREATE: %v", e)
	}
	// Give udev a moment to settle before sending events.
	time.Sleep(50 * time.Millisecond)

	inj := &UInputInjector{
		fd:          fd,
		keysymToKey: keymapByKeysym(keymap),
		screenW:     w,
		screenH:     h,
	}
	log.Infof("uinput injector ready: %dx%d, %d keys", w, h, len(inj.keysymToKey))
	return inj, nil
}

func setBit(fd int, op uintptr, code uint32) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), op, uintptr(code)); e != 0 {
		return fmt.Errorf("ioctl 0x%x %d: %v", op, code, e)
	}
	return nil
}

// writeUInputUserDev uses the legacy uinput_user_dev path (write the
// whole struct then UI_DEV_CREATE) which is universally supported on
// older and current kernels alike. uinput_user_dev is name(80) + id(8) +
// ff_effects_max(4) + absmax/absmin/absfuzz/absflat[64] = 92 + 4*64*4 =
// 1116 bytes total.
func writeUInputUserDev(fd, w, h int) error {
	const sz = 80 + 8 + 4 + uinputAbsSize*4*4
	buf := make([]byte, sz)
	copy(buf[0:80], []byte("netbird-vnc-uinput"))
	// id: BUS_VIRTUAL=0x06, vendor=0x0001, product=0x0001, version=1.
	binary.LittleEndian.PutUint16(buf[80:82], 0x06)
	binary.LittleEndian.PutUint16(buf[82:84], 0x0001)
	binary.LittleEndian.PutUint16(buf[84:86], 0x0001)
	binary.LittleEndian.PutUint16(buf[86:88], 0x0001)
	// ff_effects_max(4) at 88..92 stays zero.
	// absmax[64] at 92..348: set absX/absY.
	absmaxOff := 80 + 8 + 4
	absminOff := absmaxOff + uinputAbsSize*4
	binary.LittleEndian.PutUint32(buf[absmaxOff+absX*4:], uint32(w-1))
	binary.LittleEndian.PutUint32(buf[absmaxOff+absY*4:], uint32(h-1))
	binary.LittleEndian.PutUint32(buf[absminOff+absX*4:], 0)
	binary.LittleEndian.PutUint32(buf[absminOff+absY*4:], 0)
	if _, err := unix.Write(fd, buf); err != nil {
		return fmt.Errorf("write uinput_user_dev: %w", err)
	}
	return nil
}

// emit writes a single input_event to the device. Caller-locked.
func (u *UInputInjector) emit(typ, code uint16, value int32) error {
	ev := inputEvent{Type: typ, Code: code, Value: value}
	buf := (*[unsafe.Sizeof(inputEvent{})]byte)(unsafe.Pointer(&ev))[:]
	_, err := unix.Write(u.fd, buf)
	return err
}

func (u *UInputInjector) sync() {
	_ = u.emit(evSyn, synReport, 0)
}

// InjectKey synthesizes a press or release for the given X11 keysym.
func (u *UInputInjector) InjectKey(keysym uint32, down bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	code, ok := u.keysymToKey[keysym]
	if !ok {
		return
	}
	u.emitKeyCode(code, down)
}

// InjectKeyScancode injects a press or release using the QEMU scancode.
// uinput speaks Linux KEY_* codes natively, so we map QEMU scancode →
// KEY_* via qemuToLinuxKey. On miss (scancode we don't have a mapping
// for) we fall back to the keysym path, which is exactly the legacy
// behaviour.
func (u *UInputInjector) InjectKeyScancode(scancode, keysym uint32, down bool) {
	code := qemuScancodeToLinuxKey(scancode)
	if code == 0 {
		u.InjectKey(keysym, down)
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.emitKeyCode(uint16(code), down)
}

// emitKeyCode emits one key down/up event plus a sync. Caller holds u.mu.
func (u *UInputInjector) emitKeyCode(code uint16, down bool) {
	value := int32(0)
	if down {
		value = 1
	}
	if err := u.emit(evKey, code, value); err != nil {
		log.Tracef("uinput emit key: %v", err)
		return
	}
	u.sync()
}

// InjectPointer moves the absolute pointer and presses/releases buttons
// based on the RFB button mask delta against the previous mask.
func (u *UInputInjector) InjectPointer(buttonMask uint16, x, y, serverW, serverH int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if serverW <= 1 || serverH <= 1 {
		return
	}
	absXVal := int32(x * (u.screenW - 1) / (serverW - 1))
	absYVal := int32(y * (u.screenH - 1) / (serverH - 1))
	_ = u.emit(evAbs, absX, absXVal)
	_ = u.emit(evAbs, absY, absYVal)

	type btnMap struct {
		bit uint16
		key uint16
	}
	for _, b := range []btnMap{
		{0x01, btnLeft},
		{0x02, btnMiddle},
		{0x04, btnRight},
		{1 << 7, btnSide},
		{1 << 8, btnExtra},
	} {
		pressed := buttonMask&b.bit != 0
		was := u.prevButtons&b.bit != 0
		if pressed && !was {
			_ = u.emit(evKey, b.key, 1)
		} else if !pressed && was {
			_ = u.emit(evKey, b.key, 0)
		}
	}
	u.prevButtons = buttonMask
	u.sync()
}

// SetClipboard is a no-op on the framebuffer console: there is no system
// clipboard daemon. Use TypeText (Paste button) to deliver host text.
func (u *UInputInjector) SetClipboard(_ string) {
	// no system clipboard daemon on framebuffer console
}

// GetClipboard returns empty: no clipboard outside X11/Wayland.
func (u *UInputInjector) GetClipboard() string { return "" }

// TypeText synthesizes the given UTF-8 text as keystrokes. Only ASCII
// printable characters and newline are typed; other runes are skipped.
// This drives the "paste" button: with no console clipboard available,
// keystroke-by-keystroke entry is the only way to deliver a password to
// a TTY login prompt.
func (u *UInputInjector) TypeText(text string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	const maxChars = 4096
	count := 0
	for _, r := range text {
		if count >= maxChars {
			break
		}
		count++
		code, shift, ok := keyForRune(r)
		if !ok {
			continue
		}
		if shift {
			_ = u.emit(evKey, keyLeftShift, 1)
		}
		_ = u.emit(evKey, code, 1)
		_ = u.emit(evKey, code, 0)
		if shift {
			_ = u.emit(evKey, keyLeftShift, 0)
		}
		u.sync()
	}
}

// Close destroys the virtual uinput device and closes the file descriptor.
func (u *UInputInjector) Close() {
	u.closeOnce.Do(func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.fd >= 0 {
			_, _, _ = unix.Syscall(unix.SYS_IOCTL, uintptr(u.fd), uiDevDestroy, 0)
			_ = unix.Close(u.fd)
			u.fd = -1
		}
	})
}

// Linux KEY_* codes live in scancodes.go (shared with the QEMU scancode
// path). Don't duplicate them here.

// buildUInputKeymap returns every linux KEY_ code we want the virtual
// device to advertise during UI_SET_KEYBIT. Order doesn't matter.
func buildUInputKeymap() []uint16 {
	out := make([]uint16, 0, 128)
	// Letters: KEY_A=30, KEY_B=48, etc; not a clean range. The kernel's
	// row-by-row layout is qwertyuiop / asdfghjkl / zxcvbnm.
	letters := []uint16{
		30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50, // a..m
		49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44, // n..z
	}
	out = append(out, letters...)
	// Top-row digits: KEY_1..KEY_0 = 2..11.
	for i := uint16(2); i <= 11; i++ {
		out = append(out, i)
	}
	// Function keys F1..F12 = 59..68 + 87, 88. We only register F1..F12
	// which the kernel header enumerates as a contiguous block.
	for i := uint16(59); i <= 68; i++ {
		out = append(out, i)
	}
	out = append(out, 87, 88)
	out = append(out, []uint16{
		keyEsc, keyMinus, keyEqual, keyBackspace, keyTab, keyEnter,
		keyLeftCtrl, keyRightCtrl, keyLeftShift, keyRightShift,
		keyLeftAlt, keyRightAlt, keyLeftMeta, keyRightMeta,
		keySpace, keyCapsLock,
		keyLeftBracket, keyRightBracket, keyBackslash,
		keySemicolon, keyApostrophe, keyGrave,
		keyComma, keyDot, keySlash,
		keyHome, keyEnd, keyPageUp, keyPageDown,
		keyUp, keyDown, keyLeft, keyRight,
		keyInsert, keyDelete,
	}...)
	return out
}

// keymapByKeysym maps X11 keysyms (the values our session receives over
// RFB) onto Linux KEY_ codes. Shifted ASCII keysyms (uppercase letters,
// "!@#..." etc.) map to the same scan code as their unshifted twin: the
// client also sends a separate Shift keysym (0xffe1), so the kernel
// composes the final character from the held modifier + scan code.
func keymapByKeysym(_ []uint16) map[uint32]uint16 {
	letters := map[rune]uint16{
		'a': 30, 'b': 48, 'c': 46, 'd': 32, 'e': 18, 'f': 33, 'g': 34,
		'h': 35, 'i': 23, 'j': 36, 'k': 37, 'l': 38, 'm': 50,
		'n': 49, 'o': 24, 'p': 25, 'q': 16, 'r': 19, 's': 31, 't': 20,
		'u': 22, 'v': 47, 'w': 17, 'x': 45, 'y': 21, 'z': 44,
	}
	m := map[uint32]uint16{
		// Digits.
		'0': 11, '1': 2, '2': 3, '3': 4, '4': 5, '5': 6, '6': 7,
		'7': 8, '8': 9, '9': 10,
		// Shifted digits (US layout).
		')': 11, '!': 2, '@': 3, '#': 4, '$': 5, '%': 6, '^': 7,
		'&': 8, '*': 9, '(': 10,
		// Punctuation (US layout) and shifted twins.
		' ': keySpace,
		'-': keyMinus, '_': keyMinus,
		'=': keyEqual, '+': keyEqual,
		'[': keyLeftBracket, '{': keyLeftBracket,
		']': keyRightBracket, '}': keyRightBracket,
		'\\': keyBackslash, '|': keyBackslash,
		';': keySemicolon, ':': keySemicolon,
		'\'': keyApostrophe, '"': keyApostrophe,
		'`': keyGrave, '~': keyGrave,
		',': keyComma, '<': keyComma,
		'.': keyDot, '>': keyDot,
		'/': keySlash, '?': keySlash,
		// Special keys (X11 keysyms).
		0xff08: keyBackspace, 0xff09: keyTab, 0xff0d: keyEnter,
		0xff1b: keyEsc, 0xffff: keyDelete,
		0xff50: keyHome, 0xff57: keyEnd,
		0xff51: keyLeft, 0xff52: keyUp, 0xff53: keyRight, 0xff54: keyDown,
		0xff55: keyPageUp, 0xff56: keyPageDown, 0xff63: keyInsert,
		0xffe1: keyLeftShift, 0xffe2: keyRightShift,
		0xffe3: keyLeftCtrl, 0xffe4: keyRightCtrl,
		0xffe9: keyLeftAlt, 0xffea: keyRightAlt,
		0xffeb: keyLeftMeta, 0xffec: keyRightMeta,
	}
	// Letters: register both lowercase and uppercase keysyms onto the same
	// KEY_ code. The client sends Shift separately for uppercase.
	for r, code := range letters {
		m[uint32(r)] = code
		m[uint32(r-'a'+'A')] = code
	}
	// Function keys F1..F12 (X11 keysyms 0xffbe..0xffc9 → KEY_F1..KEY_F12).
	xF := uint32(0xffbe)
	codes := []uint16{59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 87, 88}
	for i, c := range codes {
		m[xF+uint32(i)] = c
	}
	return m
}

// keyForRune maps a printable rune to (keycode, needsShift). Used by
// TypeText to synthesize keystrokes for a paste payload.
func keyForRune(r rune) (uint16, bool, bool) {
	if r >= 'a' && r <= 'z' {
		m := map[rune]uint16{
			'a': 30, 'b': 48, 'c': 46, 'd': 32, 'e': 18, 'f': 33, 'g': 34,
			'h': 35, 'i': 23, 'j': 36, 'k': 37, 'l': 38, 'm': 50,
			'n': 49, 'o': 24, 'p': 25, 'q': 16, 'r': 19, 's': 31, 't': 20,
			'u': 22, 'v': 47, 'w': 17, 'x': 45, 'y': 21, 'z': 44,
		}
		return m[r], false, true
	}
	if r >= 'A' && r <= 'Z' {
		c, _, ok := keyForRune(unicode.ToLower(r))
		return c, true, ok
	}
	if r >= '0' && r <= '9' {
		nums := []uint16{11, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		idx := int(r - '0')
		if idx < 0 || idx >= len(nums) { //nolint:gosec // explicit bound disarms G602
			return 0, false, false
		}
		return nums[idx], false, true
	}
	if r == '\n' || r == '\r' {
		return keyEnter, false, true
	}
	if k, ok := punctUnshifted[r]; ok {
		return k, false, true
	}
	if k, ok := punctShifted[r]; ok {
		return k, true, true
	}
	return 0, false, false
}

// punctUnshifted maps ASCII punctuation that needs no Shift to its uinput
// KEY_* code. Split out of keyForRune's switch to keep the function's
// cognitive complexity below Sonar's threshold.
var punctUnshifted = map[rune]uint16{
	' ':  keySpace,
	'\t': keyTab,
	'-':  keyMinus,
	'=':  keyEqual,
	'[':  keyLeftBracket,
	']':  keyRightBracket,
	'\\': keyBackslash,
	';':  keySemicolon,
	'\'': keyApostrophe,
	'`':  keyGrave,
	',':  keyComma,
	'.':  keyDot,
	'/':  keySlash,
}

// punctShifted maps ASCII punctuation that requires Shift to its base KEY_*
// code; the caller adds the shift modifier itself.
var punctShifted = map[rune]uint16{
	'!': 2, '@': 3, '#': 4, '$': 5, '%': 6, '^': 7, '&': 8, '*': 9,
	'(': 10, ')': 11,
	'_': keyMinus, '+': keyEqual,
	'{': keyLeftBracket, '}': keyRightBracket, '|': keyBackslash,
	':': keySemicolon, '"': keyApostrophe, '~': keyGrave,
	'<': keyComma, '>': keyDot, '?': keySlash,
}

var _ InputInjector = (*UInputInjector)(nil)
