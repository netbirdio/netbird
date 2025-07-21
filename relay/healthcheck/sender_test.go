package healthcheck

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestMain(m *testing.M) {
	// override the health check interval to speed up the test
	setHealthCheckInterval(2 * time.Second)
	setHealthCheckTimeout(100 * time.Millisecond)
	code := m.Run()
	os.Exit(code)
}

func TestNewHealthPeriod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hc := NewSender(log.WithContext(ctx))
	go hc.StartHealthCheck(ctx)

	iterations := 0
	for i := 0; i < 3; i++ {
		select {
		case <-hc.HealthCheck:
			iterations++
			hc.OnHCResponse()
		case <-hc.Timeout:
			t.Fatalf("health check is timed out")
		case <-time.After(getHealthCheckInterval() + 100*time.Millisecond):
			t.Fatalf("health check not received")
		}
	}
}

func TestNewHealthFailed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hc := NewSender(log.WithContext(ctx))
	go hc.StartHealthCheck(ctx)

	select {
	case <-hc.Timeout:
	case <-time.After(getHealthCheckInterval() + getHealthCheckTimeout() + 100*time.Millisecond):
		t.Fatalf("health check is not timed out")
	}
}

func TestNewHealthcheckStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hc := NewSender(log.WithContext(ctx))
	go hc.StartHealthCheck(ctx)

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case _, ok := <-hc.HealthCheck:
		if ok {
			t.Fatalf("health check on received")
		}
	case _, ok := <-hc.Timeout:
		if ok {
			t.Fatalf("health check on received")
		}
	case <-ctx.Done():
		// expected
	case <-time.After(10 * time.Second):
		t.Fatalf("is not exited")
	}
}

func TestTimeoutReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hc := NewSender(log.WithContext(ctx))
	go hc.StartHealthCheck(ctx)

	iterations := 0
	for i := 0; i < 3; i++ {
		select {
		case <-hc.HealthCheck:
			iterations++
			hc.OnHCResponse()
		case <-hc.Timeout:
			t.Fatalf("health check is timed out")
		case <-time.After(getHealthCheckInterval() + 100*time.Millisecond):
			t.Fatalf("health check not received")
		}
	}

	select {
	case <-hc.HealthCheck:
	case <-hc.Timeout:
		// expected
	case <-ctx.Done():
		t.Fatalf("context is done")
	case <-time.After(10 * time.Second):
		t.Fatalf("is not exited")
	}
}

func TestSenderHealthCheckAttemptThreshold(t *testing.T) {
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
			originalTimeout := getHealthCheckTimeout()
			setHealthCheckInterval(1 * time.Second)
			setHealthCheckTimeout(500 * time.Millisecond)
			defer func() {
				setHealthCheckInterval(originalInterval)
				setHealthCheckTimeout(originalTimeout)
			}()

			//nolint:tenv
			os.Setenv(defaultAttemptThresholdEnv, fmt.Sprintf("%d", tc.threshold))
			defer os.Unsetenv(defaultAttemptThresholdEnv)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sender := NewSender(log.WithField("test_name", tc.name))
			go sender.StartHealthCheck(ctx)

			go func() {
				responded := false
				for {
					select {
					case <-ctx.Done():
						return
					case _, ok := <-sender.HealthCheck:
						if !ok {
							return
						}
						if tc.resetCounterOnce && !responded {
							responded = true
							sender.OnHCResponse()
						}
					}
				}
			}()

			testTimeout := sender.getTimeoutTime()*time.Duration(tc.threshold) + getHealthCheckInterval()

			select {
			case <-sender.Timeout:
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

//nolint:tenv
func TestGetAttemptThresholdFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected int
	}{
		{"Default attempt threshold when env is not set", "", defaultAttemptThreshold},
		{"Custom attempt threshold when env is set to a valid integer", "3", 3},
		{"Default attempt threshold when env is set to an invalid value", "invalid", defaultAttemptThreshold},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue == "" {
				os.Unsetenv(defaultAttemptThresholdEnv)
			} else {
				os.Setenv(defaultAttemptThresholdEnv, tt.envValue)
			}

			result := getAttemptThresholdFromEnv()
			if result != tt.expected {
				t.Fatalf("Expected %d, got %d", tt.expected, result)
			}

			os.Unsetenv(defaultAttemptThresholdEnv)
		})
	}
}
