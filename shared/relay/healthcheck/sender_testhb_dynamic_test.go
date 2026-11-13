package healthcheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/testhb"
)

// Dynamic mode: ticks land on the client phase. While the relay is muted the
// sender sends nothing and does not count the missing acks; unmute resumes.
func TestSenderTestHBDynamicMute(t *testing.T) {
	if os.Getenv("NB_TEST_HB_MODE") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSenderTestHBDynamicMute$", "-test.v")
		cmd.Env = append(os.Environ(), "NB_TEST_HB_MODE=dynamic")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return
	}

	mutePath := filepath.Join(t.TempDir(), "mute")
	t.Setenv("NB_TEST_HB_MUTE_FILE", mutePath)

	cs := testhb.ClientSchedule{PhaseMs: 400, Period: time.Second, OK: true}
	hc := NewSenderWithOpts(log.WithField("test", t.Name()), SenderOptions{
		HealthCheckInterval: 25 * time.Second,
		HealthCheckTimeout:  100 * time.Millisecond,
		AttemptThreshold:    2,
		PhaseKey:            "test-peer-key",
		ClientSchedule:      cs,
	})
	require.Equal(t, cs, hc.clientSchedule, "sender must keep the client schedule")
	// A short timeout so that missing acks would end the sender within the
	// muted window: alive -> false, failure 1, failure 2 = timeout at 1.2 s.
	hc.timeout = 400 * time.Millisecond

	// The sender starts not alive, so start it just before the phase: the
	// first tick and ack come before the timeout ticker counts a failure.
	waitForMs(350)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hc.StartHealthCheck(ctx)

	for i := 0; i < 2; i++ {
		select {
		case _, ok := <-hc.HealthCheck:
			require.True(t, ok, "sender stopped")
			got := time.Now().UnixMilli() % 1000
			assert.True(t, got >= 400 && got < 460, "tick %d at ms %d mod 1000, want 400", i, got)
			hc.OnHCResponse()
		case <-hc.Timeout:
			t.Fatal("health check timed out")
		case <-time.After(1500 * time.Millisecond):
			t.Fatalf("tick %d not received", i)
		}
	}

	require.NoError(t, os.WriteFile(mutePath, []byte("relay\n"), 0o644))
	select {
	case <-hc.HealthCheck:
		t.Fatal("muted sender sent a health check")
	case <-hc.Timeout:
		t.Fatal("muted sender counted missing acks")
	case <-time.After(1600 * time.Millisecond):
	}

	// Unmute shortly before the phase so the next tick comes before the
	// timeout ticker could count failures again.
	waitForMs(200)
	require.NoError(t, os.Remove(mutePath))
	select {
	case _, ok := <-hc.HealthCheck:
		require.True(t, ok, "sender stopped")
	case <-hc.Timeout:
		t.Fatal("health check timed out after unmute")
	case <-time.After(time.Second):
		t.Fatal("no health check after unmute")
	}
}

// waitForMs waits until the wall clock is within 20 ms after ms in its second.
func waitForMs(ms int64) {
	for {
		if d := time.Now().UnixMilli()%1000 - ms; d >= 0 && d < 20 {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// Dynamic mode, client sent no schedule (a stock client): the testhb ticker
// never fires for it, so the sender must keep the stock interval.
func TestSenderTestHBDynamicNoSchedule(t *testing.T) {
	if os.Getenv("NB_TEST_HB_MODE") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSenderTestHBDynamicNoSchedule$", "-test.v")
		cmd.Env = append(os.Environ(), "NB_TEST_HB_MODE=dynamic")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return
	}

	hc := NewSenderWithOpts(log.WithField("test", t.Name()), SenderOptions{
		HealthCheckInterval: 200 * time.Millisecond,
		HealthCheckTimeout:  100 * time.Millisecond,
		PhaseKey:            "test-peer-key",
	})
	require.Equal(t, "test-peer-key", hc.phaseKey, "sender must follow testhb")
	require.False(t, hc.clientSchedule.OK, "sender must have no client schedule")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hc.StartHealthCheck(ctx)

	for i := 0; i < 3; i++ {
		select {
		case _, ok := <-hc.HealthCheck:
			require.True(t, ok, "sender stopped")
			hc.OnHCResponse()
		case <-hc.Timeout:
			t.Fatal("health check timed out")
		case <-time.After(time.Second):
			t.Fatalf("health check %d not received", i)
		}
	}
}
