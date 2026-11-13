package healthcheck

import (
	"context"
	"hash/fnv"
	"os"
	"os/exec"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/testhb"
)

// testhb reads its env once per process, so the aligned test runs in a child
// process with the env set.
func runWithTestHBEnv(t *testing.T, name string) bool {
	t.Helper()
	if os.Getenv("NB_TEST_HB_MODE") != "" {
		return false
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), "NB_TEST_HB_MODE=aligned", "NB_TEST_HB_PERIOD_SEC=2")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child test failed: %v\n%s", err, out)
	}
	return true
}

func TestSenderTestHBAligned(t *testing.T) {
	if runWithTestHBEnv(t, "TestSenderTestHBAligned") {
		return
	}

	const key = "test-peer-key"
	period := testhb.PeriodFromEnv()
	if period != 2*time.Second {
		t.Fatalf("unexpected period %v", period)
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	offset := int64(h.Sum32()) % 2

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hc := NewSenderWithOpts(log.WithField("test", t.Name()), SenderOptions{
		HealthCheckInterval: 25 * time.Second,
		HealthCheckTimeout:  100 * time.Millisecond,
		PhaseKey:            key,
	})
	if hc.timeout < period+testHBMinAckMargin {
		t.Fatalf("timeout %v below period + %v", hc.timeout, testHBMinAckMargin)
	}
	go hc.StartHealthCheck(ctx)

	for i := 0; i < 3; i++ {
		select {
		case <-hc.HealthCheck:
			now := time.Now()
			if now.Unix()%2 != offset {
				t.Fatalf("tick %d at %v: unix %% 2 = %d, want %d", i, now, now.Unix()%2, offset)
			}
			if now.Nanosecond() > int(200*time.Millisecond) {
				t.Fatalf("tick %d at %v: too far from whole second", i, now)
			}
			hc.OnHCResponse()
		case <-hc.Timeout:
			t.Fatalf("health check timed out")
		case <-time.After(period + 500*time.Millisecond):
			t.Fatalf("tick %d not received", i)
		}
	}
}

func TestSenderPhaseKeyStockWhenOff(t *testing.T) {
	if testhb.Enabled() {
		t.Skip("testhb enabled in this process")
	}
	hc := NewSenderWithOpts(log.WithField("test", t.Name()), SenderOptions{
		HealthCheckInterval: testOpts.HealthCheckInterval,
		HealthCheckTimeout:  testOpts.HealthCheckTimeout,
		PhaseKey:            "test-peer-key",
	})
	if hc.phaseKey != "" {
		t.Fatalf("phase key set while testhb is off")
	}
	if want := testOpts.HealthCheckInterval + testOpts.HealthCheckTimeout; hc.timeout != want {
		t.Fatalf("timeout %v, want %v", hc.timeout, want)
	}
}
