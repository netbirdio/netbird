//go:build !darwin && !linux

package keepalive

import (
	"errors"
	"net"
	"time"
)

// Idle returns the keepalive idle time set on the TCP socket below conn. This
// platform has no portable way to read it.
func Idle(net.Conn) (time.Duration, error) {
	return 0, errors.ErrUnsupported
}
