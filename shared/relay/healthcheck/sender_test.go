package healthcheck

import (
	"context"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	testOpts = SenderOptions{
		HealthCheckInterval: 2 * time.Second,
		HealthCheckTimeout:  100 * time.Millisecond,
	}
)

func TestNewHealthPeriod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hc := NewSenderWithOpts(log.WithContext(ctx), testOpts)
	go hc.StartHealthCheck(ctx)

	iterations := 0
	for i := 0; i < 3; i++ {
		select {
		case <-hc.HealthCheck:
			iterations++
			hc.OnHCResponse()
		case <-hc.Timeout:
			t.Fatalf("health check is timed out")
		case <-time.After(testOpts.HealthCheckInterval + 100*time.Millisecond):
			t.Fatalf("health check not received")
		}
	}
}

func TestNewHealthFailed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hc := NewSenderWithOpts(log.WithContext(ctx), testOpts)
	go hc.StartHealthCheck(ctx)

	select {
	case <-hc.Timeout:
	case <-time.After(testOpts.HealthCheckInterval + testOpts.HealthCheckTimeout + 100*time.Millisecond):
		t.Fatalf("health check is not timed out")
	}
}

func TestNewHealthcheckStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hc := NewSenderWithOpts(log.WithContext(ctx), testOpts)
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
	hc := NewSenderWithOpts(log.WithContext(ctx), testOpts)
	go hc.StartHealthCheck(ctx)

	iterations := 0
	for i := 0; i < 3; i++ {
		select {
		case <-hc.HealthCheck:
			iterations++
			hc.OnHCResponse()
		case <-hc.Timeout:
			t.Fatalf("health check is timed out")
		case <-time.After(testOpts.HealthCheckInterval + 100*time.Millisecond):
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
			opts := SenderOptions{
				HealthCheckInterval: 1 * time.Second,
				HealthCheckTimeout:  500 * time.Millisecond,
				AttemptThreshold:    tc.threshold,
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sender := NewSenderWithOpts(log.WithField("test_name", tc.name), opts)
			senderExit := make(chan struct{})
			go func() {
				sender.StartHealthCheck(ctx)
				close(senderExit)
			}()

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

			testTimeout := (opts.HealthCheckInterval+opts.HealthCheckTimeout)*time.Duration(tc.threshold) + opts.HealthCheckInterval

			select {
			case <-sender.Timeout:
				if tc.resetCounterOnce {
					t.Errorf("should not have timed out before %s", testTimeout)
				}
			case <-time.After(testTimeout):
				if tc.resetCounterOnce {
					return
				}
				t.Errorf("should have timed out before %s", testTimeout)
			}

			cancel()
			select {
			case <-senderExit:
			case <-time.After(2 * time.Second):
				t.Fatalf("sender did not exit in time")
			}
		})
	}

}
