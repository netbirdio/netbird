//go:build linux

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// KDGKBENT values come in two encodings: a type byte with a Latin-1 character
// below it, or a Unicode code point XOR 0xf000. Anything that is not a
// character (function keys, modifiers, holes) must not map to one.
func TestConsoleKeymapRune(t *testing.T) {
	tests := []struct {
		name   string
		value  uint16
		want   rune
		wantOK bool
	}{
		{"latin a", 0x0061, 'a', true},
		{"letter a (caps-lock aware)", 0x0b61, 'a', true},
		{"unicode e-acute", 0x00e9 ^ 0xf000, 'é', true},
		{"unicode euro", 0x20ac ^ 0xf000, '€', true},
		{"unicode y-umlaut", 0x00ff ^ 0xf000, 'ÿ', true},
		{"function key", 0x0100, 0, false},
		{"braille type is not unicode", 0x0e01, 0, false},
		{"hole", 0x0200, 0, false},
		{"control char", 0x0009, 0, false},
		{"delete", 0x007f, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := consoleKeymapRune(tc.value)
			assert.Equal(t, tc.wantOK, ok, "decodes to a character")
			if tc.wantOK {
				assert.Equal(t, tc.want, got, "decoded character")
			}
		})
	}
}

// On a German console 'y' and 'z' swap places. The keysym table has to follow
// the console, or every z typed remotely comes out as a y.
func TestOverlayConsoleKeymap_FollowsLayout(t *testing.T) {
	const keyY, keyZ = 21, 44
	table := map[uint32]uint16{'y': keyY, 'z': keyZ, 0xff0d: keyEnter}
	german := map[rune]consoleKey{'z': {code: keyY}, 'y': {code: keyZ}, 'Z': {code: keyY, shift: true}}

	got := overlayConsoleKeymap(table, german)

	assert.Equal(t, uint16(keyY), got['z'], "z is on the US y key on a German layout")
	assert.Equal(t, uint16(keyZ), got['y'], "y is on the US z key on a German layout")
	assert.Equal(t, uint16(keyY), got['Z'], "uppercase follows its key; the client sends Shift itself")
	assert.Equal(t, uint16(keyEnter), got[0xff0d], "non-character keysyms are left alone")
}

// Without a console keymap the US table stands.
func TestOverlayConsoleKeymap_NilKeepsTable(t *testing.T) {
	table := map[uint32]uint16{'y': 21}
	assert.Equal(t, uint16(21), overlayConsoleKeymap(table, nil)['y'])
}
