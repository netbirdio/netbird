package healthcheck

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	log "github.com/sirupsen/logrus"
)

// An aligned sender sends on the phase from the start, with no send before the first phase,
// and a peer that answers each send stays alive.
func TestAlignedSenderSendsOnPhase(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		schedule := AlignedSchedule{Period: 60 * time.Second, Phase: 12345 * time.Millisecond}
		hc := NewAlignedSender(log.WithField("test", t.Name()), schedule)
		exited := startSender(ctx, hc)

		for i := 0; i < 4; i++ {
			select {
			case <-hc.HealthCheck:
			case <-hc.Timeout:
				t.Fatalf("send %d: timed out while every send was answered", i)
			}
			if off := time.Now().UnixMilli() % schedule.Period.Milliseconds(); off != schedule.Phase.Milliseconds() {
				t.Fatalf("send %d at offset %d ms, want %d", i, off, schedule.Phase.Milliseconds())
			}
			hc.OnHCResponse()
		}
		cancel()
		drainSender(hc, exited)
	})
}

// A schedule without a period keeps the stock interval.
func TestSenderOptionsAlignedWithoutPeriodStaysStock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hc := NewSenderWithOpts(log.WithField("test", t.Name()), SenderOptions{Aligned: &AlignedSchedule{}})
		start := time.Now()
		exited := startSender(ctx, hc)

		<-hc.HealthCheck
		if since := time.Since(start); since != defaultHealthCheckInterval {
			t.Fatalf("first send %s after the start, want the stock %s", since, defaultHealthCheckInterval)
		}
		cancel()
		drainSender(hc, exited)
	})
}

// An aligned peer that never answers times out at period plus 20 s, not before. One that
// answered once and then went silent times out at most two such spans after its answer (the
// stock alive and failure loop).
func TestAlignedSenderSilentPeerTimesOut(t *testing.T) {
	const period = 30 * time.Second
	const span = period + 20*time.Second
	opts := SenderOptions{AttemptThreshold: 1, Aligned: &AlignedSchedule{Period: period}}

	t.Run("never answers", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc := NewSenderWithOpts(log.WithField("test", t.Name()), opts)
			exited := startSender(ctx, hc)

			time.Sleep(span - time.Millisecond)
			synctest.Wait()
			select {
			case <-hc.Timeout:
				t.Fatal("timed out before period plus 20s")
			default:
			}
			time.Sleep(2 * time.Millisecond)
			synctest.Wait()
			select {
			case <-hc.Timeout:
			default:
				t.Fatal("a silent aligned peer must time out at period plus 20s")
			}
			drainSender(hc, exited)
		})
	})

	t.Run("answers once", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc := NewSenderWithOpts(log.WithField("test", t.Name()), opts)
			exited := startSender(ctx, hc)

			<-hc.HealthCheck
			hc.OnHCResponse()
			answered := time.Now()
			select {
			case <-hc.Timeout:
			case <-time.After(2*span + time.Millisecond):
				t.Fatal("no timeout within two spans after the last answer")
			}
			if since := time.Since(answered); since < span-period {
				t.Fatalf("timed out %s after the answer, sooner than the ack margin", since)
			}
			drainSender(hc, exited)
		})
	})
}
