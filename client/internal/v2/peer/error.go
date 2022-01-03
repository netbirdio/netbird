package peer

import (
	"fmt"
	"time"
)

// ConnectionTimeoutError is an error indicating that a peer Conn has been timed out
type ConnectionTimeoutError struct {
	peer    string
	timeout time.Duration
}

func (e *ConnectionTimeoutError) Error() string {
	return fmt.Sprintf("connection to peer %s timeout out after %d", e.peer, e.timeout)
}

// NewConnectionTimeoutError creates a new ConnectionTimeoutError error
func NewConnectionTimeoutError(peer string, timeout time.Duration) error {
	return &ConnectionTimeoutError{
		peer:    peer,
		timeout: timeout,
	}
}

// ConnectionClosedError is an error indicating that a peer Conn has been forcefully closed
type ConnectionClosedError struct {
	peer string
}

func (e *ConnectionClosedError) Error() string {
	return fmt.Sprintf("connection to peer %s has been closed", e.peer)
}

// NewConnectionClosedError creates a new ConnectionClosedError error
func NewConnectionClosedError(peer string) error {
	return &ConnectionClosedError{
		peer: peer,
	}
}
