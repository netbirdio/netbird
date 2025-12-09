package middleware

import (
	"context"
	"maps"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"
)

// PATUsageTracker tracks PAT usage metrics
type PATUsageTracker struct {
	usageCounters map[string]int64
	mu            sync.Mutex
	stopChan      chan struct{}
	ctx           context.Context
	histogram     metric.Int64Histogram
}

// NewPATUsageTracker creates a new PAT usage tracker with metrics
func NewPATUsageTracker(ctx context.Context, meter metric.Meter) (*PATUsageTracker, error) {
	histogram, err := meter.Int64Histogram(
		"management.pat.usage_distribution",
		metric.WithUnit("1"),
		metric.WithDescription("Distribution of PAT token usage counts per minute"),
	)
	if err != nil {
		return nil, err
	}

	tracker := &PATUsageTracker{
		usageCounters: make(map[string]int64),
		stopChan:      make(chan struct{}),
		ctx:           ctx,
		histogram:     histogram,
	}

	go tracker.reportLoop()

	return tracker, nil
}

// IncrementUsage increments the usage counter for a given token
func (t *PATUsageTracker) IncrementUsage(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.usageCounters[token]++
}

// reportLoop reports the usage buckets every minute
func (t *PATUsageTracker) reportLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.reportUsageBuckets()
		case <-t.stopChan:
			return
		}
	}
}

// reportUsageBuckets reports all token usage counts and resets counters
func (t *PATUsageTracker) reportUsageBuckets() {
	t.mu.Lock()
	snapshot := maps.Clone(t.usageCounters)

	clear(t.usageCounters)
	t.mu.Unlock()

	totalTokens := len(snapshot)
	if totalTokens > 0 {
		for id, count := range snapshot {
			t.histogram.Record(t.ctx, count)
			if count > 60 {
				log.Debugf("High PAT usage detected: token %s used %d times in the last minute", id, count)
			}
		}
		log.Debugf("PAT usage in last minute: %d unique tokens used", totalTokens)
	}
}

// Stop stops the reporting goroutine
func (t *PATUsageTracker) Stop() {
	close(t.stopChan)
}
