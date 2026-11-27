//go:build !linux

package keepalive

import (
	"errors"
	"net"
	"time"
)

// setUserTimeout is a no-op off Linux: there is no TCP_USER_TIMEOUT, so a
// vanished peer with unacked heartbeats is dropped only by the TCP
// retransmission timeout.
func setUserTimeout(*net.TCPConn, time.Duration) error {
	return nil
}

// userTimeout reports that this platform has no TCP_USER_TIMEOUT to read.
func userTimeout(*net.TCPConn) (time.Duration, error) {
	return 0, errors.ErrUnsupported
}
