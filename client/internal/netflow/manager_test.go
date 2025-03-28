package netflow

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/peer"
)

type mockIFaceMapper struct {
	address         wgaddr.Address
	isUserspaceBind bool
}

func (m *mockIFaceMapper) Name() string {
	return "wt0"
}

func (m *mockIFaceMapper) Address() wgaddr.Address {
	return m.address
}

func (m *mockIFaceMapper) IsUserspaceBind() bool {
	return m.isUserspaceBind
}

func TestManager_Update(t *testing.T) {
	mockIFace := &mockIFaceMapper{
		address: wgaddr.Address{
			Network: &net.IPNet{
				IP:   net.ParseIP("192.168.1.1"),
				Mask: net.CIDRMask(24, 32),
			},
		},
		isUserspaceBind: true,
	}

	publicKey := []byte("test-public-key")
	statusRecorder := peer.NewRecorder("")

	manager := NewManager(mockIFace, publicKey, statusRecorder)

	tests := []struct {
		name   string
		config *types.FlowConfig
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name: "disabled config",
			config: &types.FlowConfig{
				Enabled: false,
			},
		},
		{
			name: "enabled config with minimal valid settings",
			config: &types.FlowConfig{
				Enabled:        true,
				URL:            "https://example.com",
				TokenPayload:   "test-payload",
				TokenSignature: "test-signature",
				Interval:       30 * time.Second,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := manager.Update(tc.config)

			assert.NoError(t, err)

			if tc.config == nil {
				return
			}

			require.NotNil(t, manager.flowConfig)

			if tc.config.Enabled {
				assert.Equal(t, tc.config.Enabled, manager.flowConfig.Enabled)
			}

			if tc.config.URL != "" {
				assert.Equal(t, tc.config.URL, manager.flowConfig.URL)
			}

			if tc.config.TokenPayload != "" {
				assert.Equal(t, tc.config.TokenPayload, manager.flowConfig.TokenPayload)
			}
		})
	}
}

func TestManager_Update_TokenPreservation(t *testing.T) {
	mockIFace := &mockIFaceMapper{
		address: wgaddr.Address{
			Network: &net.IPNet{
				IP:   net.ParseIP("192.168.1.1"),
				Mask: net.CIDRMask(24, 32),
			},
		},
		isUserspaceBind: true,
	}

	publicKey := []byte("test-public-key")
	manager := NewManager(mockIFace, publicKey, nil)

	// First update with tokens
	initialConfig := &types.FlowConfig{
		Enabled:        false,
		TokenPayload:   "initial-payload",
		TokenSignature: "initial-signature",
	}

	err := manager.Update(initialConfig)
	require.NoError(t, err)

	// Second update without tokens should preserve them
	updatedConfig := &types.FlowConfig{
		Enabled: false,
		URL:     "https://example.com",
	}

	err = manager.Update(updatedConfig)
	require.NoError(t, err)

	// Verify tokens were preserved
	assert.Equal(t, "initial-payload", manager.flowConfig.TokenPayload)
	assert.Equal(t, "initial-signature", manager.flowConfig.TokenSignature)
}

func TestManager_NeedsNewClient(t *testing.T) {
	manager := &Manager{}

	tests := []struct {
		name     string
		previous *types.FlowConfig
		current  *types.FlowConfig
		expected bool
	}{
		{
			name:     "nil previous config",
			previous: nil,
			current:  &types.FlowConfig{},
			expected: true,
		},
		{
			name:     "previous disabled",
			previous: &types.FlowConfig{Enabled: false},
			current:  &types.FlowConfig{Enabled: true},
			expected: true,
		},
		{
			name:     "different URL",
			previous: &types.FlowConfig{Enabled: true, URL: "old-url"},
			current:  &types.FlowConfig{Enabled: true, URL: "new-url"},
			expected: true,
		},
		{
			name:     "different TokenPayload",
			previous: &types.FlowConfig{Enabled: true, TokenPayload: "old-payload"},
			current:  &types.FlowConfig{Enabled: true, TokenPayload: "new-payload"},
			expected: true,
		},
		{
			name:     "different TokenSignature",
			previous: &types.FlowConfig{Enabled: true, TokenSignature: "old-signature"},
			current:  &types.FlowConfig{Enabled: true, TokenSignature: "new-signature"},
			expected: true,
		},
		{
			name:     "same config",
			previous: &types.FlowConfig{Enabled: true, URL: "url", TokenPayload: "payload", TokenSignature: "signature"},
			current:  &types.FlowConfig{Enabled: true, URL: "url", TokenPayload: "payload", TokenSignature: "signature"},
			expected: false,
		},
		{
			name:     "only interval changed",
			previous: &types.FlowConfig{Enabled: true, URL: "url", TokenPayload: "payload", TokenSignature: "signature", Interval: 30 * time.Second},
			current:  &types.FlowConfig{Enabled: true, URL: "url", TokenPayload: "payload", TokenSignature: "signature", Interval: 60 * time.Second},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager.flowConfig = tc.current
			result := manager.needsNewClient(tc.previous)
			assert.Equal(t, tc.expected, result)
		})
	}
}
