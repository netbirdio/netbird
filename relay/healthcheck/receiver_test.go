package healthcheck

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestNewReceiver(t *testing.T) {
	setHeartBeatTimeout(5 * time.Second)
	r := NewReceiver(log.WithContext(context.Background()))

	select {
	case <-r.OnTimeout:
		t.Error("unexpected timeout")
	case <-time.After(1 * time.Second):

	}
}

func TestNewReceiverNotReceive(t *testing.T) {
	setHeartBeatTimeout(1 * time.Second)
	r := NewReceiver(log.WithContext(context.Background()))

	select {
	case <-r.OnTimeout:
	case <-time.After(2 * time.Second):
		t.Error("timeout not received")
	}
}

func TestNewReceiverAck(t *testing.T) {
	setHeartBeatTimeout(2 * time.Second)
	r := NewReceiver(log.WithContext(context.Background()))

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
			originalInterval := getHealthCheckInterval()
			originalTimeout := getHeartBeatTimeout()
			setHealthCheckInterval(1 * time.Second)
			setHeartBeatTimeout(getHealthCheckInterval() + 500*time.Millisecond)
			defer func() {
				setHealthCheckInterval(originalInterval)
				setHeartBeatTimeout(originalTimeout)
			}()
			//nolint:tenv
			os.Setenv(defaultAttemptThresholdEnv, fmt.Sprintf("%d", tc.threshold))
			defer os.Unsetenv(defaultAttemptThresholdEnv)

			receiver := NewReceiver(log.WithField("test_name", tc.name))

			testTimeout := originalTimeout*time.Duration(tc.threshold) + getHealthCheckInterval()

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
