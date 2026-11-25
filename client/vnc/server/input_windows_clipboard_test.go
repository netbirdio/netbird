//go:build windows

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Clipboard text is set by whichever local process owns the clipboard, and
// nothing makes it end in a NUL. Decoding must stop at the block's end, not
// run on looking for a terminator.
func TestUTF16UpToNUL(t *testing.T) {
	assert.Equal(t, "hi", utf16UpToNUL([]uint16{'h', 'i', 0, 'x'}), "stops at the first NUL")
	assert.Equal(t, "hi", utf16UpToNUL([]uint16{'h', 'i'}), "an unterminated block decodes to its end and no further")
	assert.Equal(t, "", utf16UpToNUL([]uint16{0, 'x'}), "a leading NUL is an empty string")
	assert.Equal(t, "", utf16UpToNUL(nil))
}
