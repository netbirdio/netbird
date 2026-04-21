package server

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const sendRateLogInterval = 5 * time.Minute

// sendRateTracker tracks per-key message counts and logs the busiest peers periodically.
type sendRateTracker struct {
	mu     sync.Mutex
	counts map[string]int64
}

func newSendRateTracker() *sendRateTracker {
	return &sendRateTracker{counts: make(map[string]int64)}
}

func (t *sendRateTracker) increment(key string) {
	t.mu.Lock()
	t.counts[key]++
	t.mu.Unlock()
}

// resetAndSnapshot atomically returns current counts and resets the tracker.
func (t *sendRateTracker) resetAndSnapshot() map[string]int64 {
	t.mu.Lock()
	snap := t.counts
	t.counts = make(map[string]int64, len(snap))
	t.mu.Unlock()
	return snap
}

// logSendRates periodically logs peers that have at least half the rate of the busiest peer.
func (t *sendRateTracker) logSendRates(ctx context.Context) {
	ticker := time.NewTicker(sendRateLogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := t.resetAndSnapshot()
			if len(snap) == 0 {
				continue
			}

			var maxCount int64
			for _, count := range snap {
				if count > maxCount {
					maxCount = count
				}
			}

			threshold := int64(float64(maxCount) * 0.95)
			intervalMin := sendRateLogInterval.Minutes()

			log.Debugf("send rate stats: %d unique peers in last %.0fs, max rate %.1f msg/min",
				len(snap), sendRateLogInterval.Seconds(), float64(maxCount)/intervalMin)
			logged := 0
			for key, count := range snap {
				if count >= threshold {
					log.Debugf("peer [%s] %.1f msg/min", key, float64(count)/intervalMin)
					logged++
					if logged >= 100 {
						break
					}
				}
			}
		}
	}
}
