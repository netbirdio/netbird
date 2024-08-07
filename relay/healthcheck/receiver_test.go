package healthcheck

import (
	"testing"
	"time"
)

func TestNewReceiver(t *testing.T) {
	heartbeatTimeout = 5 * time.Second
	r := NewReceiver()

	select {
	case <-r.OnTimeout:
		t.Error("unexpected timeout")
	case <-time.After(1 * time.Second):

	}
}

func TestNewReceiverNotReceive(t *testing.T) {
	heartbeatTimeout = 1 * time.Second
	r := NewReceiver()

	select {
	case <-r.OnTimeout:
	case <-time.After(2 * time.Second):
		t.Error("timeout not received")
	}
}

func TestNewReceiverAck(t *testing.T) {
	heartbeatTimeout = 2 * time.Second
	r := NewReceiver()

	r.Heartbeat()

	select {
	case <-r.OnTimeout:
		t.Error("unexpected timeout")
	case <-time.After(3 * time.Second):
	}
}
