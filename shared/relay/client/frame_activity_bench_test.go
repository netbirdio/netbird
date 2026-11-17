package client

import (
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

type benchClock struct{}

func (benchClock) Now() time.Time                      { return time.Now() }
func (benchClock) AfterFunc(d time.Duration, f func()) { time.AfterFunc(d, f) }

// BenchmarkRelayFrameActivity runs the per-frame activity note of relay read
// loops on a mobile build, where the default watcher exists. Each parallel
// loop stands for one relay connection, the first one is registered.
func BenchmarkRelayFrameActivity(b *testing.B) {
	w := hbwatch.New(benchClock{}, time.Minute)
	b.Cleanup(hbwatch.SetDefault(w))
	home := newAlignedEcho(v2, messages.HashID("bench-peer"), time.Minute, 0, log.WithField("bench", b.Name()))
	unregister := w.Register(hbwatch.Relay, hbwatch.Registration{Stale: func() {}, Stream: home, Frames: home.frameCount})
	b.Cleanup(unregister)
	var loops atomic.Int32
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		e := home
		if loops.Add(1) > 1 {
			e = newAlignedEcho(v2, messages.HashID("bench-peer"), time.Minute, 0, home.log)
		}
		for pb.Next() {
			e.frame()
		}
	})
}
