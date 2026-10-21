//go:build !windows

package server

// keysymForASCIIRune maps an ASCII rune to (X11 keysym for the unshifted
// version, needsShift). Used by TypeText implementations on each platform
// so the caller can explicitly press Shift instead of relying on the
// server-side modifier state. Returns ok=false for runes outside the
// supported set; non-ASCII text is dropped by TypeText.
func keysymForASCIIRune(r rune) (uint32, bool, bool) {
	if r >= 'a' && r <= 'z' {
		return uint32(r), false, true
	}
	if r >= 'A' && r <= 'Z' {
		return uint32(r - 'A' + 'a'), true, true
	}
	if r >= '0' && r <= '9' {
		return uint32(r), false, true
	}
	switch r {
	case ' ':
		return 0x20, false, true
	case '\n', '\r':
		return 0xff0d, false, true // Return
	case '\t':
		return 0xff09, false, true // Tab
	case '-', '=', '[', ']', '\\', ';', '\'', '`', ',', '.', '/':
		return uint32(r), false, true
	case '!':
		return '1', true, true
	case '@':
		return '2', true, true
	case '#':
		return '3', true, true
	case '$':
		return '4', true, true
	case '%':
		return '5', true, true
	case '^':
		return '6', true, true
	case '&':
		return '7', true, true
	case '*':
		return '8', true, true
	case '(':
		return '9', true, true
	case ')':
		return '0', true, true
	case '_':
		return '-', true, true
	case '+':
		return '=', true, true
	case '{':
		return '[', true, true
	case '}':
		return ']', true, true
	case '|':
		return '\\', true, true
	case ':':
		return ';', true, true
	case '"':
		return '\'', true, true
	case '~':
		return '`', true, true
	case '<':
		return ',', true, true
	case '>':
		return '.', true, true
	case '?':
		return '/', true, true
	}
	return 0, false, false
}
