package debug

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrintHealth_WithCertsAndClients(t *testing.T) {
	var buf bytes.Buffer
	c := NewClient("localhost:8444", false, &buf)

	data := map[string]any{
		"status":                "ok",
		"uptime":                "1h30m",
		"management_connected":  true,
		"all_clients_healthy":   true,
		"certs_total":           float64(3),
		"certs_ready":           float64(2),
		"certs_pending":         float64(1),
		"certs_failed":          float64(0),
		"certs_ready_domains":   []any{"a.example.com", "b.example.com"},
		"certs_pending_domains": []any{"c.example.com"},
		"clients": map[string]any{
			"acc-1": map[string]any{
				"healthy":              true,
				"management_connected": true,
				"signal_connected":     true,
				"relays_connected":     float64(1),
				"relays_total":         float64(2),
				"peers_connected":      float64(3),
				"peers_total":          float64(5),
				"peers_p2p":            float64(2),
				"peers_relayed":        float64(1),
				"peers_degraded":       float64(0),
			},
		},
	}

	c.printHealth(data)
	out := buf.String()

	assert.Contains(t, out, "Status: ok")
	assert.Contains(t, out, "Uptime: 1h30m")
	assert.Contains(t, out, "yes") // management_connected
	assert.Contains(t, out, "2 ready, 1 pending, 0 failed (3 total)")
	assert.Contains(t, out, "a.example.com")
	assert.Contains(t, out, "c.example.com")
	assert.Contains(t, out, "acc-1")
}

func TestPrintHealth_Minimal(t *testing.T) {
	var buf bytes.Buffer
	c := NewClient("localhost:8444", false, &buf)

	data := map[string]any{
		"status":               "ok",
		"uptime":               "5m",
		"management_connected": false,
		"all_clients_healthy":  false,
	}

	c.printHealth(data)
	out := buf.String()

	assert.Contains(t, out, "Status: ok")
	assert.Contains(t, out, "Uptime: 5m")
	assert.NotContains(t, out, "Certificates")
	assert.NotContains(t, out, "ACCOUNT ID")
}
