package healthcheck

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	log "github.com/sirupsen/logrus"
)

// SetAligned moves a stock sender to the aligned schedule: one send at the
// switch, then every send lands on the phase, a peer that answers each send
// stays alive, and a later schedule without a period is ignored.
func TestSenderSetAlignedSendsOnPhase(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hc := NewSender(log.WithField("test", t.Name()))
		schedule := AlignedSchedule{Period: 60 * time.Second, Phase: 12345 * time.Millisecond}
		hc.SetAligned(schedule)
		hc.SetAligned(AlignedSchedule{})
		switched := time.Now()
		exited := startSender(ctx, hc)

		<-hc.HealthCheck
		if since := time.Since(switched); since != 0 {
			t.Fatalf("first send %s after the switch, want at once", since)
		}
		hc.OnHCResponse()
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

// An aligned peer that never answers times out at period plus 20 s, not
// before. One that answered once and then went silent times out at most two
// such spans after its answer (the stock alive and failure loop).
func TestSenderSetAlignedSilentPeerTimesOut(t *testing.T) {
	const period = 30 * time.Second
	const span = period + 20*time.Second

	t.Run("never answers", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hc := NewSender(log.WithField("test", t.Name()))
			hc.SetAligned(AlignedSchedule{Period: period})
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
			hc := NewSender(log.WithField("test", t.Name()))
			hc.SetAligned(AlignedSchedule{Period: period})
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
