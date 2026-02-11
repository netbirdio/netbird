package metrics

import (
	"context"
	"io"
	"time"
)

// noopMetrics is a no-op implementation of metricsImplementation
type noopMetrics struct{}

func (s *noopMetrics) RecordConnectionStages(
	_ context.Context,
	_ ConnectionType,
	_ bool,
	_ ConnectionStageTimestamps,
) {
	// No-op
}

func (s *noopMetrics) RecordSyncDuration(_ context.Context, _ time.Duration) {
	// No-op
}

func (s *noopMetrics) Export(_ io.Writer) error {
	return nil
}
