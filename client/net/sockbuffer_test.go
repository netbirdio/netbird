package net

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRelaySocketBufferSize(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		setEnv   bool
		expected int
	}{
		{
			name:     "unset uses default",
			setEnv:   false,
			expected: defaultRelaySocketBufferSize,
		},
		{
			name:     "empty uses default",
			envValue: "",
			setEnv:   true,
			expected: defaultRelaySocketBufferSize,
		},
		{
			name:     "zero disables sizing",
			envValue: "0",
			setEnv:   true,
			expected: 0,
		},
		{
			name:     "explicit value is honored",
			envValue: "1048576",
			setEnv:   true,
			expected: 1048576,
		},
		{
			name:     "non-numeric value uses default",
			envValue: "garbage",
			setEnv:   true,
			expected: defaultRelaySocketBufferSize,
		},
		{
			name:     "negative value uses default",
			envValue: "-5",
			setEnv:   true,
			expected: defaultRelaySocketBufferSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(relaySocketBufferEnv, tt.envValue)
			}

			assert.Equal(t, tt.expected, relaySocketBufferSize())
		})
	}
}

func TestSizeRelaySocketBuffersSmoke(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()

	assert.NotPanics(t, func() {
		SizeRelaySocketBuffers(conn)
	})

	assert.NotPanics(t, func() {
		SizeRelaySocketBuffers(struct{}{})
	})
}
