//go:build !js

package metrics

import "github.com/prometheus/client_golang/prometheus"

// NewClientMetrics creates a new ClientMetrics instance
func NewClientMetrics(agentInfo AgentInfo) *ClientMetrics {
	return &ClientMetrics{
		impl:      newPrometheusMetrics(newInfluxDBMetrics()),
		agentInfo: agentInfo,
	}
}

// PrometheusGatherer returns the registry with the mirrored Prometheus
// metrics, or nil when unavailable.
func (c *ClientMetrics) PrometheusGatherer() prometheus.Gatherer {
	if c == nil {
		return nil
	}
	if pm, ok := c.impl.(*prometheusMetrics); ok {
		return pm.Gatherer()
	}
	return nil
}
