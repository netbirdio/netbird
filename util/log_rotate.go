//go:build !js

package util

import (
	"io"
	"path/filepath"

	"github.com/DeRuina/timberjack"
)

// newRotatedOutput returns a size/age-rotating log file writer backed by
// timberjack. Kept out of the js build: timberjack pulls in
// github.com/klauspost/compress/zstd (~1.5MB) for compressed rotation, which is
// useless in the browser (no persistent log files). See log_rotate_js.go.
func newRotatedOutput(logPath string) io.Writer {
	maxLogSize := getLogMaxSize()
	timberjackLogger := &timberjack.Logger{
		// Log file absolute path, os agnostic
		Filename:    filepath.ToSlash(logPath),
		MaxSize:     maxLogSize, // MB
		MaxBackups:  10,
		MaxAge:      30, // days
		Compression: "gzip",
	}
	return timberjackLogger
}
