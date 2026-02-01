//go:build darwin && !ios

package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetActiveNetworkServices(t *testing.T) {
	services, err := GetActiveNetworkServices()
	assert.NoError(t, err)
	assert.NotEmpty(t, services, "should have at least one network service")

	// Check that services don't contain invalid entries
	for _, service := range services {
		assert.NotEmpty(t, service)
		assert.NotContains(t, service, "*")
	}
}

func TestManager_EnableDisableWebProxy(t *testing.T) {
	// Skip this test in CI as it requires admin privileges
	if testing.Short() {
		t.Skip("skipping proxy test in short mode")
	}

	m := NewManager(nil)
	assert.NotNil(t, m)
	assert.False(t, m.IsEnabled())

	// This test would require admin privileges to actually enable the proxy
	// So we just test the basic state management
}

func TestShutdownState_Name(t *testing.T) {
	state := &ShutdownState{}
	assert.Equal(t, "proxy_state", state.Name())
}

func TestShutdownState_Cleanup_EmptyServices(t *testing.T) {
	state := &ShutdownState{
		ModifiedServices: []string{},
	}
	err := state.Cleanup()
	assert.NoError(t, err)
}

func TestContains(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   bool
	}{
		{"Enabled: Yes", "Enabled: Yes", true},
		{"Enabled: No", "Enabled: Yes", false},
		{"Server: 127.0.0.1\nEnabled: Yes\nPort: 8080", "Enabled: Yes", true},
		{"", "Enabled: Yes", false},
		{"Enabled: Yes", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			got := contains(tt.s, tt.substr)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsProxyEnabled(t *testing.T) {
	tests := []struct {
		output string
		want   bool
	}{
		{"Enabled: Yes\nServer: 127.0.0.1\nPort: 8080", true},
		{"Enabled: No\nServer: \nPort: 0", false},
		{"Server: 127.0.0.1\nEnabled: Yes\nPort: 8080", true},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.output, func(t *testing.T) {
			got := isProxyEnabled(tt.output)
			assert.Equal(t, tt.want, got)
		})
	}
}
