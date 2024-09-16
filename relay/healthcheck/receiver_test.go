package healthcheck

import (
	"os"
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

func TestDefaultAttemptThreshold(t *testing.T) {
	originalTimeout := heartbeatTimeout
	heartbeatTimeout = 50 * time.Millisecond
	defer func() { heartbeatTimeout = originalTimeout }()

	os.Unsetenv(defaultAttemptThresholdEnv)

	r := NewReceiver()
	defer r.Stop()

	if r.attemptThreshold != defaultAttemptThreshold {
		t.Fatalf("Expected attemptThreshold to be %d, got %d", defaultAttemptThreshold, r.attemptThreshold)
	}
}

func TestCustomAttemptThreshold(t *testing.T) {
	originalTimeout := heartbeatTimeout
	heartbeatTimeout = 50 * time.Millisecond
	defer func() { heartbeatTimeout = originalTimeout }()

	os.Setenv(defaultAttemptThresholdEnv, "3")
	defer os.Unsetenv(defaultAttemptThresholdEnv)

	r := NewReceiver()
	defer r.Stop()

	if r.attemptThreshold != 3 {
		t.Fatalf("Expected attemptThreshold to be 3, got %d", r.attemptThreshold)
	}
}

func TestInvalidAttemptThreshold(t *testing.T) {
	originalTimeout := heartbeatTimeout
	heartbeatTimeout = 50 * time.Millisecond
	defer func() { heartbeatTimeout = originalTimeout }()

	os.Setenv(defaultAttemptThresholdEnv, "invalid")
	defer os.Unsetenv(defaultAttemptThresholdEnv)

	r := NewReceiver()
	defer r.Stop()

	if r.attemptThreshold != defaultAttemptThreshold {
		t.Fatalf("Expected attemptThreshold to be default (%d), got %d", defaultAttemptThreshold, r.attemptThreshold)
	}
}

func TestHeartbeatTimeout(t *testing.T) {
	originalTimeout := heartbeatTimeout
	heartbeatTimeout = 50 * time.Millisecond
	defer func() { heartbeatTimeout = originalTimeout }()

	os.Setenv(defaultAttemptThresholdEnv, "3")
	defer os.Unsetenv(defaultAttemptThresholdEnv)

	r := NewReceiver()
	defer r.Stop()

	timeoutCh := r.OnTimeout

	r.Heartbeat()

	time.Sleep(heartbeatTimeout / 2)

	r.Heartbeat()

	time.Sleep(heartbeatTimeout + 10*time.Millisecond)

	select {
	case <-timeoutCh:
		t.Fatal("Received timeout before reaching attemptThreshold")
	default:
	}

	time.Sleep(heartbeatTimeout * time.Duration(r.attemptThreshold))

	select {
	case <-timeoutCh:
	case <-time.After(heartbeatTimeout):
		t.Fatal("Did not receive timeout after missing heartbeats equal to attemptThreshold")
	}
}

func TestFailureCounterReset(t *testing.T) {
	originalTimeout := heartbeatTimeout
	heartbeatTimeout = 50 * time.Millisecond
	defer func() { heartbeatTimeout = originalTimeout }()

	os.Setenv(defaultAttemptThresholdEnv, "2")
	defer os.Unsetenv(defaultAttemptThresholdEnv)

	// Create a new Receiver
	r := NewReceiver()
	defer r.Stop()

	timeoutCh := r.OnTimeout

	// Do not send any heartbeat, wait for one heartbeatTimeout
	time.Sleep(heartbeatTimeout + 10*time.Millisecond)

	r.Heartbeat()

	time.Sleep(heartbeatTimeout * 2)

	select {
	case <-timeoutCh:
		t.Fatal("Received timeout unexpectedly after failure counter reset")
	default:
	}

	time.Sleep(heartbeatTimeout * time.Duration(r.attemptThreshold))

	select {
	case <-timeoutCh:
	case <-time.After(heartbeatTimeout):
		t.Fatal("Did not receive timeout after missing heartbeats equal to attemptThreshold")
	}
}
