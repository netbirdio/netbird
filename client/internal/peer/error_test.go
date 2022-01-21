package peer

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewConnectionClosedError(t *testing.T) {
	err := NewConnectionClosedError("X")
	assert.Equal(t, &ConnectionClosedError{peer: "X"}, err)
}

func TestNewConnectionDisconnectedError(t *testing.T) {
	err := NewConnectionDisconnectedError("X")
	assert.Equal(t, &ConnectionDisconnectedError{peer: "X"}, err)
}

func TestNewConnectionTimeoutErrorC(t *testing.T) {
	err := NewConnectionTimeoutError("X", time.Second)
	assert.Equal(t, &ConnectionTimeoutError{peer: "X", timeout: time.Second}, err)
}

func TestNewConnectionAlreadyClosed(t *testing.T) {
	err := NewConnectionAlreadyClosed("X")
	assert.Equal(t, &ConnectionAlreadyClosedError{peer: "X"}, err)
}
