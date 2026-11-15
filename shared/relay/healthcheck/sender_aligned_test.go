package healthcheck

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestAlignedSenderSendsOnPhase(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		schedule := AlignedSchedule{Period: 60 * time.Second, Phase: 12345 * time.Millisecond}
		hc := NewAlignedSender(log.WithField("test", t.Name()), schedule)
		exited := startSender(ctx, hc)

		for i := 0; i < 3; i++ {
			select {
			case <-hc.HealthCheck:
			case <-hc.Timeout:
				t.Fatalf("send %d: timed out while acks were sent", i)
			}
			now := time.Now()
			if off := now.UnixMilli() % schedule.Period.Milliseconds(); off != schedule.Phase.Milliseconds() {
				t.Fatalf("send %d at offset %d ms, want %d", i, off, schedule.Phase.Milliseconds())
			}
			hc.OnHCResponse()
		}
		cancel()
		drainSender(hc, exited)
	})
}

func TestAlignedSenderTimeoutCoversPeriod(t *testing.T) {
	hc := NewAlignedSender(log.WithField("test", t.Name()), AlignedSchedule{Period: 60 * time.Second})
	if want := 60*time.Second + defaultHealthCheckTimeout; hc.timeout != want {
		t.Errorf("timeout %s, want %s", hc.timeout, want)
	}

	hc = NewSenderWithOpts(log.WithField("test", t.Name()), SenderOptions{
		HealthCheckTimeout: time.Second,
		Aligned:            &AlignedSchedule{Period: 30 * time.Second},
	})
	if want := 30*time.Second + alignedMinAckMargin; hc.timeout != want {
		t.Errorf("timeout %s, want %s with the minimum ack margin", hc.timeout, want)
	}
}

func TestSenderWithoutScheduleStaysStock(t *testing.T) {
	hc := NewSenderWithOpts(log.WithField("test", t.Name()), SenderOptions{
		HealthCheckInterval: testOpts.HealthCheckInterval,
		HealthCheckTimeout:  testOpts.HealthCheckTimeout,
		Aligned:             &AlignedSchedule{},
	})
	if hc.aligned != nil {
		t.Fatalf("a zero period must not turn the aligned schedule on")
	}
	if want := testOpts.HealthCheckInterval + testOpts.HealthCheckTimeout; hc.timeout != want {
		t.Fatalf("timeout %v, want %v", hc.timeout, want)
	}
}

// SetAligned switches a stock sender to the aligned schedule and later moves
// its phase, from the next tick on.
func TestSenderSetAlignedMovesSchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hc := NewSender(log.WithField("test", t.Name()))
		exited := startSender(ctx, hc)

		first := AlignedSchedule{Period: 60 * time.Second, Phase: 7 * time.Second}
		second := AlignedSchedule{Period: 60 * time.Second, Phase: 41500 * time.Millisecond}
		hc.SetAligned(first)
		expectSendAt(t, hc, first)
		hc.SetAligned(AlignedSchedule{})
		hc.SetAligned(second)
		expectSendAt(t, hc, second)
		expectSendAt(t, hc, second)
		if want := second.Period + defaultHealthCheckTimeout; hc.timeout != want {
			t.Errorf("timeout %s, want %s", hc.timeout, want)
		}
		cancel()
		drainSender(hc, exited)
	})
}

func expectSendAt(t *testing.T, hc *Sender, s AlignedSchedule) {
	t.Helper()
	select {
	case <-hc.HealthCheck:
	case <-hc.Timeout:
		t.Fatal("timed out while acks were sent")
	}
	if off := time.Now().UnixMilli() % s.Period.Milliseconds(); off != s.Phase.Milliseconds() {
		t.Fatalf("send at offset %d ms, want %d", off, s.Phase.Milliseconds())
	}
	hc.OnHCResponse()
}
