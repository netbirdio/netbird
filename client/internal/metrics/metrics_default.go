//go:build !js

package metrics

// NewClientMetrics creates a new ClientMetrics instance
func NewClientMetrics(agentInfo AgentInfo) *ClientMetrics {
	return &ClientMetrics{
		impl:      newInfluxDBMetrics(),
		agentInfo: agentInfo,
	}
}
