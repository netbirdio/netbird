//go:build darwin && !ios

package server

// Apple keyboard virtual-key codes used with CGEventCreateKeyboardEvent.
// These are the kVK_ANSI_* / kVK_* values from Apple's
// HIToolbox/Events.h; reproduced here so we don't need to drag in the
// HIToolbox framework just for the constants.
const (
	macKeyA              uint16 = 0x00
	macKeyS              uint16 = 0x01
	macKeyD              uint16 = 0x02
	macKeyF              uint16 = 0x03
	macKeyH              uint16 = 0x04
	macKeyG              uint16 = 0x05
	macKeyZ              uint16 = 0x06
	macKeyX              uint16 = 0x07
	macKeyC              uint16 = 0x08
	macKeyV              uint16 = 0x09
	macKeyNonUSBackslash uint16 = 0x0A // ISO_Section / 102nd
	macKeyB              uint16 = 0x0B
	macKeyQ              uint16 = 0x0C
	macKeyW              uint16 = 0x0D
	macKeyE              uint16 = 0x0E
	macKeyR              uint16 = 0x0F
	macKeyY              uint16 = 0x10
	macKeyT              uint16 = 0x11
	macKey1              uint16 = 0x12
	macKey2              uint16 = 0x13
	macKey3              uint16 = 0x14
	macKey4              uint16 = 0x15
	macKey6              uint16 = 0x16
	macKey5              uint16 = 0x17
	macKeyEqual          uint16 = 0x18
	macKey9              uint16 = 0x19
	macKey7              uint16 = 0x1A
	macKeyMinus          uint16 = 0x1B
	macKey8              uint16 = 0x1C
	macKey0              uint16 = 0x1D
	macKeyRightBracket   uint16 = 0x1E
	macKeyO              uint16 = 0x1F
	macKeyU              uint16 = 0x20
	macKeyLeftBracket    uint16 = 0x21
	macKeyI              uint16 = 0x22
	macKeyP              uint16 = 0x23
	macKeyReturn         uint16 = 0x24
	macKeyL              uint16 = 0x25
	macKeyJ              uint16 = 0x26
	macKeyApostrophe     uint16 = 0x27
	macKeyK              uint16 = 0x28
	macKeySemicolon      uint16 = 0x29
	macKeyBackslash      uint16 = 0x2A
	macKeyComma          uint16 = 0x2B
	macKeySlash          uint16 = 0x2C
	macKeyN              uint16 = 0x2D
	macKeyM              uint16 = 0x2E
	macKeyPeriod         uint16 = 0x2F
	macKeyTab            uint16 = 0x30
	macKeySpace          uint16 = 0x31
	macKeyGrave          uint16 = 0x32
	macKeyDelete         uint16 = 0x33 // Backspace
	macKeyEscape         uint16 = 0x35
	macKeyCommand        uint16 = 0x37
	macKeyShift          uint16 = 0x38
	macKeyCapsLock       uint16 = 0x39
	macKeyOption         uint16 = 0x3A // Alt
	macKeyControl        uint16 = 0x3B
	macKeyRightShift     uint16 = 0x3C
	macKeyRightOption    uint16 = 0x3D
	macKeyRightControl   uint16 = 0x3E
	macKeyFunction       uint16 = 0x3F
	macKeyF17            uint16 = 0x40
	macKeyKPDecimal      uint16 = 0x41
	macKeyKPMultiply     uint16 = 0x43
	macKeyKPPlus         uint16 = 0x45
	macKeyKPClear        uint16 = 0x47 // numlock
	macKeyVolumeUp       uint16 = 0x48
	macKeyVolumeDown     uint16 = 0x49
	macKeyMute           uint16 = 0x4A
	macKeyKPDivide       uint16 = 0x4B
	macKeyKPEnter        uint16 = 0x4C
	macKeyKPMinus        uint16 = 0x4E
	macKeyF18            uint16 = 0x4F
	macKeyF19            uint16 = 0x50
	macKeyKPEqual        uint16 = 0x51
	macKeyKP0            uint16 = 0x52
	macKeyKP1            uint16 = 0x53
	macKeyKP2            uint16 = 0x54
	macKeyKP3            uint16 = 0x55
	macKeyKP4            uint16 = 0x56
	macKeyKP5            uint16 = 0x57
	macKeyKP6            uint16 = 0x58
	macKeyKP7            uint16 = 0x59
	macKeyF20            uint16 = 0x5A
	macKeyKP8            uint16 = 0x5B
	macKeyKP9            uint16 = 0x5C
	macKeyF5             uint16 = 0x60
	macKeyF6             uint16 = 0x61
	macKeyF7             uint16 = 0x62
	macKeyF3             uint16 = 0x63
	macKeyF8             uint16 = 0x64
	macKeyF9             uint16 = 0x65
	macKeyF11            uint16 = 0x67
	macKeyF13            uint16 = 0x69 // PrintScreen on most layouts
	macKeyF16            uint16 = 0x6A
	macKeyF14            uint16 = 0x6B
	macKeyF10            uint16 = 0x6D
	macKeyF12            uint16 = 0x6F
	macKeyF15            uint16 = 0x71
	macKeyHelp           uint16 = 0x72 // Insert on PC keyboards
	macKeyHome           uint16 = 0x73
	macKeyPageUp         uint16 = 0x74
	macKeyForwardDelete  uint16 = 0x75
	macKeyF4             uint16 = 0x76
	macKeyEnd            uint16 = 0x77
	macKeyF2             uint16 = 0x78
	macKeyPageDown       uint16 = 0x79
	macKeyF1             uint16 = 0x7A
	macKeyLeft           uint16 = 0x7B
	macKeyRight          uint16 = 0x7C
	macKeyDown           uint16 = 0x7D
	macKeyUp             uint16 = 0x7E
)

// qemuToMacVK maps PC AT Set 1 scancodes (as QEMU emits them, with the
// 0xE0 prefix merged into the high byte) onto Apple virtual-key codes.
// Layout-independent: the scancode names the physical key, the user's
// active keyboard layout on the Mac decides what the key produces.
var qemuToMacVK = map[uint32]uint16{
	// Single-byte (non-extended).
	0x01: macKeyEscape,
	0x02: macKey1,
	0x03: macKey2,
	0x04: macKey3,
	0x05: macKey4,
	0x06: macKey5,
	0x07: macKey6,
	0x08: macKey7,
	0x09: macKey8,
	0x0A: macKey9,
	0x0B: macKey0,
	0x0C: macKeyMinus,
	0x0D: macKeyEqual,
	0x0E: macKeyDelete, // PC Backspace -> mac "Delete"
	0x0F: macKeyTab,
	0x10: macKeyQ,
	0x11: macKeyW,
	0x12: macKeyE,
	0x13: macKeyR,
	0x14: macKeyT,
	0x15: macKeyY,
	0x16: macKeyU,
	0x17: macKeyI,
	0x18: macKeyO,
	0x19: macKeyP,
	0x1A: macKeyLeftBracket,
	0x1B: macKeyRightBracket,
	0x1C: macKeyReturn,
	0x1D: macKeyControl,
	0x1E: macKeyA,
	0x1F: macKeyS,
	0x20: macKeyD,
	0x21: macKeyF,
	0x22: macKeyG,
	0x23: macKeyH,
	0x24: macKeyJ,
	0x25: macKeyK,
	0x26: macKeyL,
	0x27: macKeySemicolon,
	0x28: macKeyApostrophe,
	0x29: macKeyGrave,
	0x2A: macKeyShift,
	0x2B: macKeyBackslash,
	0x2C: macKeyZ,
	0x2D: macKeyX,
	0x2E: macKeyC,
	0x2F: macKeyV,
	0x30: macKeyB,
	0x31: macKeyN,
	0x32: macKeyM,
	0x33: macKeyComma,
	0x34: macKeyPeriod,
	0x35: macKeySlash,
	0x36: macKeyRightShift,
	0x37: macKeyKPMultiply,
	0x38: macKeyOption, // Left Alt -> Option
	0x39: macKeySpace,
	0x3A: macKeyCapsLock,
	0x3B: macKeyF1,
	0x3C: macKeyF2,
	0x3D: macKeyF3,
	0x3E: macKeyF4,
	0x3F: macKeyF5,
	0x40: macKeyF6,
	0x41: macKeyF7,
	0x42: macKeyF8,
	0x43: macKeyF9,
	0x44: macKeyF10,
	0x45: macKeyKPClear, // PC NumLock -> mac Clear
	0x47: macKeyKP7,
	0x48: macKeyKP8,
	0x49: macKeyKP9,
	0x4A: macKeyKPMinus,
	0x4B: macKeyKP4,
	0x4C: macKeyKP5,
	0x4D: macKeyKP6,
	0x4E: macKeyKPPlus,
	0x4F: macKeyKP1,
	0x50: macKeyKP2,
	0x51: macKeyKP3,
	0x52: macKeyKP0,
	0x53: macKeyKPDecimal,
	0x56: macKeyNonUSBackslash,
	0x57: macKeyF11,
	0x58: macKeyF12,

	// Extended (0xE0 prefix).
	0xE01C: macKeyKPEnter,
	0xE01D: macKeyRightControl,
	0xE020: macKeyMute,
	0xE02E: macKeyVolumeDown,
	0xE030: macKeyVolumeUp,
	0xE035: macKeyKPDivide,
	0xE037: macKeyF13, // PrintScreen
	0xE038: macKeyRightOption,
	0xE047: macKeyHome,
	0xE048: macKeyUp,
	0xE049: macKeyPageUp,
	0xE04B: macKeyLeft,
	0xE04D: macKeyRight,
	0xE04F: macKeyEnd,
	0xE050: macKeyDown,
	0xE051: macKeyPageDown,
	0xE052: macKeyHelp, // PC Insert -> mac Help
	0xE053: macKeyForwardDelete,
	0xE05B: macKeyCommand, // Left Windows -> Command
	0xE05C: macKeyCommand, // Right Windows -> Command (no separate code)
}
