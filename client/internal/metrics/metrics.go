package metrics

import (
	"io"

	"github.com/VictoriaMetrics/metrics"
)

// ClientMetrics holds all client-side metrics
type ClientMetrics struct {
	// ICE negotiation metrics
	iceNegotiationDuration *metrics.Histogram
}

// NewClientMetrics creates a new ClientMetrics instance
func NewClientMetrics() *ClientMetrics {
	return &ClientMetrics{
		// ICE negotiation metrics
		iceNegotiationDuration: metrics.NewHistogram(`netbird_client_ice_negotiation_duration_seconds`),
	}
}

// RecordICENegotiationDuration records the time taken for ICE negotiation
func (m *ClientMetrics) RecordICENegotiationDuration(seconds float64) {
	m.iceNegotiationDuration.Update(seconds)
}

// Export writes all metrics in Prometheus format to the provided writer
func (m *ClientMetrics) Export(w io.Writer) error {
	metrics.WritePrometheus(w, true)
	return nil
}
