//go:build !js && !ios && !android

package server

// QEMU Extended Key Event carries hardware scancodes encoded as PC AT Set 1.
// Single-byte codes cover the standard keys; the "extended" prefix 0xE0 is
// merged into the high byte (so 0xE048 is the extended-Up arrow). This file
// translates those scancodes into the per-platform identifiers each input
// backend wants:
//
//   - Linux uinput wants Linux KEY_* codes (defined in
//     linux/input-event-codes.h). uinput is what we use for virtual Xvfb
//     sessions on Linux.
//   - X11 XTest wants XKB keycodes, which on a standard layout equal
//     Linux KEY_* + 8 (the per-server offset between the Linux event code
//     and the X server's keycode space).
//   - Windows SendInput accepts the PC AT scancode directly via
//     KEYEVENTF_SCANCODE, so no mapping table is needed there; the
//     extended-key bit is set when the QEMU scancode high byte is 0xE0.
//   - macOS CGEventCreateKeyboardEvent takes a "virtual keycode" from
//     Apple's HID set, which is unrelated to PC AT and needs its own
//     table (see qemuToMacVK in input_darwin.go).
//
// Linux KEY_* codes. Only the ones we reference, since the full
// linux/input-event-codes.h list isn't useful here. Naming mirrors the
// existing constants in input_uinput_linux.go (mixed case, no underscores).
const (
	keyEsc          = 1
	key1            = 2
	key2            = 3
	key3            = 4
	key4            = 5
	key5            = 6
	key6            = 7
	key7            = 8
	key8            = 9
	key9            = 10
	key0            = 11
	keyMinus        = 12
	keyEqual        = 13
	keyBackspace    = 14
	keyTab          = 15
	keyQ            = 16
	keyW            = 17
	keyE            = 18
	keyR            = 19
	keyT            = 20
	keyY            = 21
	keyU            = 22
	keyI            = 23
	keyO            = 24
	keyP            = 25
	keyLeftBracket  = 26
	keyRightBracket = 27
	keyEnter        = 28
	keyLeftCtrl     = 29
	keyA            = 30
	keyS            = 31
	keyD            = 32
	keyF            = 33
	keyG            = 34
	keyH            = 35
	keyJ            = 36
	keyK            = 37
	keyL            = 38
	keySemicolon    = 39
	keyApostrophe   = 40
	keyGrave        = 41
	keyLeftShift    = 42
	keyBackslash    = 43
	keyZ            = 44
	keyX            = 45
	keyC            = 46
	keyV            = 47
	keyB            = 48
	keyN            = 49
	keyM            = 50
	keyComma        = 51
	keyDot          = 52
	keySlash        = 53
	keyRightShift   = 54
	keyKPAsterisk   = 55
	keyLeftAlt      = 56
	keySpace        = 57
	keyCapsLock     = 58
	keyF1           = 59
	keyF2           = 60
	keyF3           = 61
	keyF4           = 62
	keyF5           = 63
	keyF6           = 64
	keyF7           = 65
	keyF8           = 66
	keyF9           = 67
	keyF10          = 68
	keyNumLock      = 69
	keyScrollLock   = 70
	keyKP7          = 71
	keyKP8          = 72
	keyKP9          = 73
	keyKPMinus      = 74
	keyKP4          = 75
	keyKP5          = 76
	keyKP6          = 77
	keyKPPlus       = 78
	keyKP1          = 79
	keyKP2          = 80
	keyKP3          = 81
	keyKP0          = 82
	keyKPDot        = 83
	key102nd        = 86
	keyF11          = 87
	keyF12          = 88
	keyKPEnter      = 96
	keyRightCtrl    = 97
	keyKPSlash      = 98
	keySysRq        = 99
	keyRightAlt     = 100
	keyHome         = 102
	keyUp           = 103
	keyPageUp       = 104
	keyLeft         = 105
	keyRight        = 106
	keyEnd          = 107
	keyDown         = 108
	keyPageDown     = 109
	keyInsert       = 110
	keyDelete       = 111
	keyMute         = 113
	keyVolumeDown   = 114
	keyVolumeUp     = 115
	keyLeftMeta     = 125
	keyRightMeta    = 126
	keyCompose      = 127
)

// qemuToLinuxKey maps the PC AT Set 1 scancode QEMU sends to a Linux KEY_*
// code. The high byte 0xE0 marks "extended" scancodes (arrows, the right-
// side modifier keys, keypad enter/divide, browser keys, etc.).
//
// Keep this table dense so a reviewer sees the whole keyboard at a glance,
// and so adding a new key is a single line.
var qemuToLinuxKey = map[uint32]int{
	// Single-byte (non-extended) scancodes.
	0x01: keyEsc,
	0x02: key1,
	0x03: key2,
	0x04: key3,
	0x05: key4,
	0x06: key5,
	0x07: key6,
	0x08: key7,
	0x09: key8,
	0x0A: key9,
	0x0B: key0,
	0x0C: keyMinus,
	0x0D: keyEqual,
	0x0E: keyBackspace,
	0x0F: keyTab,
	0x10: keyQ,
	0x11: keyW,
	0x12: keyE,
	0x13: keyR,
	0x14: keyT,
	0x15: keyY,
	0x16: keyU,
	0x17: keyI,
	0x18: keyO,
	0x19: keyP,
	0x1A: keyLeftBracket,
	0x1B: keyRightBracket,
	0x1C: keyEnter,
	0x1D: keyLeftCtrl,
	0x1E: keyA,
	0x1F: keyS,
	0x20: keyD,
	0x21: keyF,
	0x22: keyG,
	0x23: keyH,
	0x24: keyJ,
	0x25: keyK,
	0x26: keyL,
	0x27: keySemicolon,
	0x28: keyApostrophe,
	0x29: keyGrave,
	0x2A: keyLeftShift,
	0x2B: keyBackslash,
	0x2C: keyZ,
	0x2D: keyX,
	0x2E: keyC,
	0x2F: keyV,
	0x30: keyB,
	0x31: keyN,
	0x32: keyM,
	0x33: keyComma,
	0x34: keyDot,
	0x35: keySlash,
	0x36: keyRightShift,
	0x37: keyKPAsterisk,
	0x38: keyLeftAlt,
	0x39: keySpace,
	0x3A: keyCapsLock,
	0x3B: keyF1,
	0x3C: keyF2,
	0x3D: keyF3,
	0x3E: keyF4,
	0x3F: keyF5,
	0x40: keyF6,
	0x41: keyF7,
	0x42: keyF8,
	0x43: keyF9,
	0x44: keyF10,
	0x45: keyNumLock,
	0x46: keyScrollLock,
	0x47: keyKP7,
	0x48: keyKP8,
	0x49: keyKP9,
	0x4A: keyKPMinus,
	0x4B: keyKP4,
	0x4C: keyKP5,
	0x4D: keyKP6,
	0x4E: keyKPPlus,
	0x4F: keyKP1,
	0x50: keyKP2,
	0x51: keyKP3,
	0x52: keyKP0,
	0x53: keyKPDot,
	0x56: key102nd,
	0x57: keyF11,
	0x58: keyF12,

	// Extended (0xE0-prefixed) scancodes.
	0xE01C: keyKPEnter,
	0xE01D: keyRightCtrl,
	0xE020: keyMute,
	0xE02E: keyVolumeDown,
	0xE030: keyVolumeUp,
	0xE035: keyKPSlash,
	0xE037: keySysRq, // PrintScreen
	0xE038: keyRightAlt,
	0xE047: keyHome,
	0xE048: keyUp,
	0xE049: keyPageUp,
	0xE04B: keyLeft,
	0xE04D: keyRight,
	0xE04F: keyEnd,
	0xE050: keyDown,
	0xE051: keyPageDown,
	0xE052: keyInsert,
	0xE053: keyDelete,
	0xE05B: keyLeftMeta,
	0xE05C: keyRightMeta,
	0xE05D: keyCompose,
}

// qemuScancodeToLinuxKey is the lookup the uinput and X11 paths use.
// Returns 0 (which Linux treats as KEY_RESERVED) when the scancode has no
// mapping, signalling "fall back to the keysym path".
func qemuScancodeToLinuxKey(scancode uint32) int {
	return qemuToLinuxKey[scancode]
}

// qemuScancodeIsExtended reports whether a QEMU scancode is in the
// 0xE0-prefixed extended range. Used by Windows SendInput to set the
// KEYEVENTF_EXTENDEDKEY flag.
func qemuScancodeIsExtended(scancode uint32) bool {
	return scancode&0xFF00 == 0xE000
}

// qemuScancodeLowByte returns the byte SendInput's wScan field actually
// stores: the low byte of the scancode regardless of any extended prefix.
func qemuScancodeLowByte(scancode uint32) uint16 {
	return uint16(scancode & 0xFF)
}
