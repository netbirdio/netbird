package healthcheck

import (
	"context"
	"testing"
	"testing/synctest"
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
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		hc.StartHealthCheck(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatalf("is not exited")
	}

	if _, ok := <-hc.HealthCheck; ok {
		t.Fatalf("health check on received")
	}
	if _, ok := <-hc.Timeout; ok {
		t.Fatalf("health check on received")
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

func TestSender_ExitsOnCancelWhenHealthCheckIsNotConsumed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hc := NewSenderWithOpts(log.WithField("test_name", t.Name()), SenderOptions{
			HealthCheckInterval: time.Second,
			HealthCheckTimeout:  time.Hour,
		})
		exited := startSender(ctx, hc)

		// The first tick fills the one slot buffer, the second one finds it full.
		time.Sleep(2*time.Second + 500*time.Millisecond)
		synctest.Wait()
		cancel()
		synctest.Wait()

		select {
		case <-exited:
		default:
			t.Errorf("the sender must exit on cancel even when nobody reads HealthCheck")
		}
		drainSender(hc, exited)
	})
}

func TestSender_TimesOutWhenHealthCheckIsNotConsumed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hc := NewSenderWithOpts(log.WithField("test_name", t.Name()), SenderOptions{
			HealthCheckInterval: time.Second,
			HealthCheckTimeout:  3 * time.Second,
			AttemptThreshold:    2,
		})
		exited := startSender(ctx, hc)

		// The timeout ticker fires every 4s, so the second failed attempt is at 8s.
		time.Sleep(8*time.Second + time.Millisecond)
		synctest.Wait()

		select {
		case _, ok := <-hc.Timeout:
			if !ok {
				t.Errorf("the timeout must be signalled before the channel is closed")
			}
		default:
			t.Errorf("a full HealthCheck channel must not stop the timeout")
		}
		drainSender(hc, exited)
	})
}

func TestSender_KeepsOnePendingHealthCheck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hc := NewSenderWithOpts(log.WithField("test_name", t.Name()), SenderOptions{
			HealthCheckInterval: time.Second,
			HealthCheckTimeout:  time.Hour,
		})
		exited := startSender(ctx, hc)

		time.Sleep(3*time.Second + 500*time.Millisecond)
		synctest.Wait()
		if pending := len(hc.HealthCheck); pending != 1 {
			t.Errorf("missed ticks must leave one pending health check, got %d", pending)
		}

		<-hc.HealthCheck
		time.Sleep(time.Second)
		synctest.Wait()
		if pending := len(hc.HealthCheck); pending != 1 {
			t.Errorf("the next tick must request a health check again, got %d", pending)
		}

		cancel()
		drainSender(hc, exited)
	})
}

func startSender(ctx context.Context, hc *Sender) <-chan struct{} {
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		hc.StartHealthCheck(ctx)
	}()
	return exited
}

// drainSender unblocks a sender that is stuck on a full HealthCheck channel and waits
// for it to exit, so a failing test leaves no goroutine behind.
func drainSender(hc *Sender, exited <-chan struct{}) {
	for range hc.HealthCheck {
	}
	<-exited
}
