package netutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"syscall"
)

// ValidatePort converts an int32 proto port to uint16, returning an error
// if the value is out of the valid 1–65535 range.
func ValidatePort(port int32) (uint16, error) {
	if port <= 0 || port > math.MaxUint16 {
		return 0, fmt.Errorf("invalid port %d: must be 1–65535", port)
	}
	return uint16(port), nil
}

// IsExpectedError returns true for errors that are normal during
// connection teardown and should not be logged as warnings.
func IsExpectedError(err error) bool {
	return errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNABORTED)
}

// IsTimeout checks whether the error is a network timeout.
func IsTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
