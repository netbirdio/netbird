package healthcheck

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// Mutex to protect global variable access in tests
var testMutex sync.Mutex

func TestNewReceiver(t *testing.T) {
	testMutex.Lock()
	originalTimeout := heartbeatTimeout
	heartbeatTimeout = 5 * time.Second
	testMutex.Unlock()

	defer func() {
		testMutex.Lock()
		heartbeatTimeout = originalTimeout
		testMutex.Unlock()
	}()

	r := NewReceiver(log.WithContext(context.Background()))
	defer r.Stop()

	select {
	case <-r.OnTimeout:
		t.Error("unexpected timeout")
	case <-time.After(1 * time.Second):
		// Test passes if no timeout received
	}
}

func TestNewReceiverNotReceive(t *testing.T) {
	testMutex.Lock()
	originalTimeout := heartbeatTimeout
	heartbeatTimeout = 1 * time.Second
	testMutex.Unlock()

	defer func() {
		testMutex.Lock()
		heartbeatTimeout = originalTimeout
		testMutex.Unlock()
	}()

	r := NewReceiver(log.WithContext(context.Background()))
	defer r.Stop()

	select {
	case <-r.OnTimeout:
		// Test passes if timeout is received
	case <-time.After(2 * time.Second):
		t.Error("timeout not received")
	}
}

func TestNewReceiverAck(t *testing.T) {
	testMutex.Lock()
	originalTimeout := heartbeatTimeout
	heartbeatTimeout = 2 * time.Second
	testMutex.Unlock()

	defer func() {
		testMutex.Lock()
		heartbeatTimeout = originalTimeout
		testMutex.Unlock()
	}()

	r := NewReceiver(log.WithContext(context.Background()))
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
			testMutex.Lock()
			originalInterval := healthCheckInterval
			originalTimeout := heartbeatTimeout
			healthCheckInterval = 1 * time.Second
			heartbeatTimeout = healthCheckInterval + 500*time.Millisecond
			testMutex.Unlock()

			defer func() {
				testMutex.Lock()
				healthCheckInterval = originalInterval
				heartbeatTimeout = originalTimeout
				testMutex.Unlock()
			}()
			//nolint:tenv
			os.Setenv(defaultAttemptThresholdEnv, fmt.Sprintf("%d", tc.threshold))
			defer os.Unsetenv(defaultAttemptThresholdEnv)

			receiver := NewReceiver(log.WithField("test_name", tc.name))

			testTimeout := heartbeatTimeout*time.Duration(tc.threshold) + healthCheckInterval

			if tc.resetCounterOnce {
				receiver.Heartbeat()
				t.Logf("reset counter once")
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
