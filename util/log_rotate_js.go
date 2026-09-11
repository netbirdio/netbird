//go:build js

package util

import (
	"io"
	"os"
)

// newRotatedOutput has no log rotation on js/wasm. The browser has no
// persistent log files worth rotating, and the timberjack rotator drags in
// github.com/klauspost/compress/zstd (~1.5MB). Fall back to a plain append-only
// file, matching the rotation-disabled path in setupLogFile; if the file cannot
// be opened (e.g. no writable fs), discard rather than fail logging.
func newRotatedOutput(logPath string) io.Writer {
	file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return io.Discard
	}
	return file
}
