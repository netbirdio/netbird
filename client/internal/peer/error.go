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
	return fmt.Sprintf("connection to peer %s timed out after %s", e.peer, e.timeout.String())
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

// ConnectionDisconnectedError is an error indicating that a peer Conn has ctx from the remote
type ConnectionDisconnectedError struct {
	peer string
}

func (e *ConnectionDisconnectedError) Error() string {
	return fmt.Sprintf("disconnected from peer %s", e.peer)
}

// NewConnectionDisconnectedError creates a new ConnectionDisconnectedError error
func NewConnectionDisconnectedError(peer string) error {
	return &ConnectionDisconnectedError{
		peer: peer,
	}
}

// ConnectionAlreadyClosedError is an error indicating that a peer Conn has been already closed and the invocation of the Close() method has been performed over a closed connection
type ConnectionAlreadyClosedError struct {
	peer string
}

func (e *ConnectionAlreadyClosedError) Error() string {
	return fmt.Sprintf("connection to peer %s has been already closed", e.peer)
}

// NewConnectionAlreadyClosed creates a new ConnectionAlreadyClosedError error
func NewConnectionAlreadyClosed(peer string) error {
	return &ConnectionAlreadyClosedError{
		peer: peer,
	}
}
