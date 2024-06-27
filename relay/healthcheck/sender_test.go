package healthcheck

import (
	"context"
	"testing"
	"time"
)

func TestNewHealthPeriod(t *testing.T) {
	// override the health check interval to speed up the test
	healthCheckInterval = 1 * time.Second
	healthCheckTimeout = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hc := NewSender(ctx)

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
	// override the health check interval to speed up the test
	healthCheckInterval = 1 * time.Second
	healthCheckTimeout = 500 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hc := NewSender(ctx)

	select {
	case <-hc.Timeout:
	case <-time.After(healthCheckInterval + healthCheckTimeout + 100*time.Millisecond):
		t.Fatalf("health check is not timed out")
	}
}

func TestNewHealthcheckStop(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	hc := NewSender(ctx)

	time.Sleep(1 * time.Second)
	cancel()

	select {
	case <-hc.HealthCheck:
		t.Fatalf("is not closed")
	case <-hc.Timeout:
		t.Fatalf("is not closed")
	case <-ctx.Done():
		// expected
	case <-time.After(1 * time.Second):
		t.Fatalf("is not exited")
	}
}
