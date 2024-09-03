package healthcheck

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// override the health check interval to speed up the test
	healthCheckInterval = 2 * time.Second
	healthCheckTimeout = 100 * time.Millisecond
	code := m.Run()
	os.Exit(code)
}

func TestNewHealthPeriod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hc := NewSender()
	go hc.StartHealthCheck(ctx)

	iterations := 0
	for i := 0; i < 3; i++ {
		select {
		case <-hc.HealthCheck:
			iterations++
			hc.OnHCResponse()
		case <-hc.Timeout:
			t.Fatalf("health check is timed out")
		case <-time.After(healthCheckInterval + 100*time.Millisecond):
			t.Fatalf("health check not received")
		}
	}
}

func TestNewHealthFailed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hc := NewSender()
	go hc.StartHealthCheck(ctx)

	select {
	case <-hc.Timeout:
	case <-time.After(healthCheckInterval + healthCheckTimeout + 100*time.Millisecond):
		t.Fatalf("health check is not timed out")
	}
}

func TestNewHealthcheckStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hc := NewSender()
	go hc.StartHealthCheck(ctx)

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-hc.HealthCheck:
		t.Fatalf("health check on received")
	case <-hc.Timeout:
		t.Fatalf("health check timedout")
	case <-ctx.Done():
		// expected
	case <-time.After(10 * time.Second):
		t.Fatalf("is not exited")
	}
}

func TestTimeoutReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hc := NewSender()
	go hc.StartHealthCheck(ctx)

	iterations := 0
	for i := 0; i < 3; i++ {
		select {
		case <-hc.HealthCheck:
			iterations++
			hc.OnHCResponse()
		case <-hc.Timeout:
			t.Fatalf("health check is timed out")
		case <-time.After(healthCheckInterval + 100*time.Millisecond):
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
