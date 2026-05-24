package server

import (
	"context"
	"math"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	defaultSendRateLogInterval = 5 * time.Minute
	defaultSendRateTopPercent  = 0.95
	envSendRateLogInterval     = "NB_SIGNAL_SEND_RATE_LOG_INTERVAL"
	envSendRateTopPercent      = "NB_SIGNAL_SEND_RATE_LOG_TOP_PERCENT"
)

// sendRateTracker tracks per-key message counts and logs the busiest peers periodically.
type sendRateTracker struct {
	mu     sync.Mutex
	counts map[string]int64

	// atomic so they can be updated by the setting overrider without locking
	intervalNs atomic.Int64
	// topPercent stored as float64 bits for atomic access
	topPercentBits atomic.Uint64
}

func newSendRateTracker() *sendRateTracker {
	interval := defaultSendRateLogInterval
	if v := os.Getenv(envSendRateLogInterval); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			interval = parsed
		}
	}

	topPercent := defaultSendRateTopPercent
	if v := os.Getenv(envSendRateTopPercent); v != "" {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil && parsed > 0 && parsed <= 1 {
			topPercent = parsed
		}
	}

	log.Debugf("send rate tracker: interval=%s, top_percent=%.2f", interval, topPercent)

	t := &sendRateTracker{
		counts: make(map[string]int64),
	}
	t.intervalNs.Store(int64(interval))
	t.topPercentBits.Store(math.Float64bits(topPercent))
	return t
}

func (t *sendRateTracker) getInterval() time.Duration {
	return time.Duration(t.intervalNs.Load())
}

func (t *sendRateTracker) setInterval(d time.Duration) {
	t.intervalNs.Store(int64(d))
}

func (t *sendRateTracker) getTopPercent() float64 {
	return math.Float64frombits(t.topPercentBits.Load())
}

func (t *sendRateTracker) setTopPercent(p float64) {
	t.topPercentBits.Store(math.Float64bits(p))
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

// logSendRates periodically logs peers in the top percentile of the busiest peer.
func (t *sendRateTracker) logSendRates(ctx context.Context) {
	currentInterval := t.getInterval()
	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if newInterval := t.getInterval(); newInterval != currentInterval {
				currentInterval = newInterval
				ticker.Reset(currentInterval)
			}

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

			topPercent := t.getTopPercent()
			threshold := int64(float64(maxCount) * topPercent)
			intervalMin := currentInterval.Minutes()

			log.Debugf("send rate stats: %d unique peers in last %.0fs, max rate %.1f msg/min",
				len(snap), currentInterval.Seconds(), float64(maxCount)/intervalMin)
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
