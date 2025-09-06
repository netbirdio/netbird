package healthcheck

import (
	"context"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestNewReceiver(t *testing.T) {

	opts := ReceiverOptions{
		HeartbeatTimeout: 5 * time.Second,
	}
	r := NewReceiverWithOpts(log.WithContext(context.Background()), opts)
	defer r.Stop()

	select {
	case <-r.OnTimeout:
		t.Error("unexpected timeout")
	case <-time.After(1 * time.Second):
		// Test passes if no timeout received
	}
}

func TestNewReceiverNotReceive(t *testing.T) {
	opts := ReceiverOptions{
		HeartbeatTimeout: 1 * time.Second,
	}
	r := NewReceiverWithOpts(log.WithContext(context.Background()), opts)
	defer r.Stop()

	select {
	case <-r.OnTimeout:
		// Test passes if timeout is received
	case <-time.After(2 * time.Second):
		t.Error("timeout not received")
	}
}

func TestNewReceiverAck(t *testing.T) {
	opts := ReceiverOptions{
		HeartbeatTimeout: 2 * time.Second,
	}
	r := NewReceiverWithOpts(log.WithContext(context.Background()), opts)
	defer r.Stop()

	r.Heartbeat()

	select {
	case <-r.OnTimeout:
		t.Error("unexpected timeout")
	case <-time.After(3 * time.Second):
	}
}

func TestReceiverHealthCheckAttemptThreshold(t *testing.T) {
	testsCases := []struct {
		name             string
		threshold        int
		resetCounterOnce bool
	}{
		{"Default attempt threshold", defaultAttemptThreshold, false},
		{"Custom attempt threshold", 3, false},
		{"Should reset threshold once", 2, true},
	}

	for _, tc := range testsCases {
		t.Run(tc.name, func(t *testing.T) {
			healthCheckInterval := 1 * time.Second

			opts := ReceiverOptions{
				HeartbeatTimeout: healthCheckInterval + 500*time.Millisecond,
				AttemptThreshold: tc.threshold,
			}

			receiver := NewReceiverWithOpts(log.WithField("test_name", tc.name), opts)

			testTimeout := opts.HeartbeatTimeout*time.Duration(tc.threshold) + healthCheckInterval

			if tc.resetCounterOnce {
				receiver.Heartbeat()
			}

			select {
			case <-receiver.OnTimeout:
				if tc.resetCounterOnce {
					t.Fatalf("should not have timed out before %s", testTimeout)
				}
			case <-time.After(testTimeout):
				if tc.resetCounterOnce {
					return
				}
				t.Fatalf("should have timed out before %s", testTimeout)
			}
		})
	}
}
