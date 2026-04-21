package server

import (
	"context"
	"os"
	"strconv"
	"sync"
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
	mu         sync.Mutex
	counts     map[string]int64
	interval   time.Duration
	topPercent float64
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

	return &sendRateTracker{
		counts:     make(map[string]int64),
		interval:   interval,
		topPercent: topPercent,
	}
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
	ticker := time.NewTicker(t.interval)
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

			threshold := int64(float64(maxCount) * t.topPercent)
			intervalMin := t.interval.Minutes()

			log.Debugf("send rate stats: %d unique peers in last %.0fs, max rate %.1f msg/min",
				len(snap), t.interval.Seconds(), float64(maxCount)/intervalMin)
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
