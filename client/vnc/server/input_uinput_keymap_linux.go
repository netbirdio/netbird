//go:build linux

package server

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// consoleTTY is the console device whose keymap uinput events are decoded
// with: /dev/tty0 always names the foreground virtual terminal.
const consoleTTY = "/dev/tty0"

// kdgkbent is KDGKBENT from linux/kd.h, which reads one keymap entry.
const kdgkbent = 0x4B46

// Keymap tables (linux/keyboard.h), indexed by the modifier bits held: the
// character a key produces unmodified, with Shift (KG_SHIFT), with AltGr
// (KG_ALTGR), and with both.
const (
	kNormTab       = 0
	kShiftTab      = 1
	kAltGrTab      = 2
	kShiftAltGrTab = 3
)

// Key types (linux/keyboard.h). KT_LATIN and KT_LETTER carry a Latin-1
// character in the low byte; ktNrTypes is NR_TYPES, one past the last real
// type, which is how Unicode entries are told apart.
const (
	ktLatin   = 0
	ktLetter  = 11
	ktNrTypes = 15
)

// kbEntry mirrors struct kbentry.
type kbEntry struct {
	table uint8
	index uint8
	value uint16
}

// consoleKey is the key that types a character on the console's active layout,
// and the modifier that has to be held for it.
type consoleKey struct {
	code  uint16
	shift bool
	altGr bool
}

// readConsoleKeymap reads the active console keymap and returns, for every
// printable character it can type, the key that types it. Tables are read from
// fewest modifiers to most (plain, Shift, AltGr, Shift+AltGr), and the first
// one to produce a character wins, so a character reachable more than one way
// gets the simplest.
//
// The kernel decodes uinput key codes with this same keymap, which is what makes
// it the right source. A fixed US table types the wrong characters on any other
// layout, including into a password prompt on the console.
func readConsoleKeymap(tty string) (map[rune]consoleKey, error) {
	fd, err := unix.Open(tty, unix.O_RDONLY|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tty, err)
	}
	defer unix.Close(fd)

	tables := []struct {
		table uint8
		key   consoleKey
	}{
		{kNormTab, consoleKey{}},
		{kShiftTab, consoleKey{shift: true}},
		{kAltGrTab, consoleKey{altGr: true}},
		{kShiftAltGrTab, consoleKey{shift: true, altGr: true}},
	}

	out := make(map[rune]consoleKey)
	for _, tab := range tables {
		for code := 1; code < 256; code++ {
			e := kbEntry{table: tab.table, index: uint8(code)}
			if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), kdgkbent, uintptr(unsafe.Pointer(&e))); errno != 0 {
				if tab.table == kNormTab && code == 1 {
					return nil, fmt.Errorf("KDGKBENT on %s: %w", tty, errno)
				}
				continue
			}
			r, ok := consoleKeymapRune(e.value)
			if !ok {
				continue
			}
			if _, taken := out[r]; taken {
				continue
			}
			key := tab.key
			key.code = uint16(code)
			out[r] = key
		}
	}
	if len(out) == 0 {
		return nil, errors.New("console keymap has no printable entries")
	}
	return out, nil
}

// consoleKeymapRune decodes a KDGKBENT value into the character it types.
// Unicode entries come back as the code point XOR 0xf000, which leaves their
// type byte at NR_TYPES or above, the same test dumpkeys applies; Latin-1 ones
// carry a real type and the character in the low byte. Everything else
// (function keys, modifiers, dead keys, holes) types no character of its own.
func consoleKeymapRune(v uint16) (rune, bool) {
	var r rune
	switch t := v >> 8; {
	case t >= ktNrTypes:
		r = rune(v ^ 0xf000)
	case t == ktLatin || t == ktLetter:
		r = rune(v & 0xff)
	default:
		return 0, false
	}
	return r, r >= 0x20 && r != 0x7f
}

// keymapCodes returns the key codes a console keymap uses, so the uinput device
// can advertise every one of them.
func keymapCodes(km map[rune]consoleKey) []uint16 {
	codes := make([]uint16, 0, len(km))
	for _, k := range km {
		codes = append(codes, k.code)
	}
	return codes
}
