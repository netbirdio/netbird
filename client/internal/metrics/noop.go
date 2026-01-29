package metrics

import (
	"context"
	"io"
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

func (s *noopMetrics) Export(_ io.Writer) error {
	return nil
}
