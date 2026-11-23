//go:build windows

package server

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isPipeDisconnect reports the named-pipe errors a client that closed its end
// produces: the pipe is being closed, has ended, or was never connected.
func isPipeDisconnect(err error) bool {
	return errors.Is(err, windows.ERROR_NO_DATA) ||
		errors.Is(err, windows.ERROR_BROKEN_PIPE) ||
		errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED)
}
