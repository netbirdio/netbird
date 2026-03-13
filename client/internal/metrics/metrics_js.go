//go:build js

package metrics

// NewClientMetrics returns nil on WASM builds — all ClientMetrics methods are nil-safe.
func NewClientMetrics(AgentInfo) *ClientMetrics {
	return nil
}
