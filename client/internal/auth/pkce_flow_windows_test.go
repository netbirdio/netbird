//go:build windows

package auth

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseExcludedPortRanges(t *testing.T) {
	tests := []struct {
		name           string
		netshOutput    string
		expectedRanges []excludedPortRange
		expectError    bool
	}{
		{
			name: "Valid netsh output with multiple ranges",
			netshOutput: `
Protocol tcp Dynamic Port Range
---------------------------------
Start Port      : 49152
Number of Ports : 16384

Protocol tcp Excluded Port Ranges
---------------------------------
Start Port    End Port
----------    --------
     5357        5357      *
    50000       50059      *
`,
			expectedRanges: []excludedPortRange{
				{start: 5357, end: 5357},
				{start: 50000, end: 50059},
			},
			expectError: false,
		},
		{
			name: "Empty output",
			netshOutput: `
Protocol tcp Dynamic Port Range
---------------------------------
Start Port      : 49152
Number of Ports : 16384
`,
			expectedRanges: nil,
			expectError:    false,
		},
		{
			name: "Single range",
			netshOutput: `
Protocol tcp Excluded Port Ranges
---------------------------------
Start Port    End Port
----------    --------
     8080        8090
`,
			expectedRanges: []excludedPortRange{
				{start: 8080, end: 8090},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranges, err := parseExcludedPortRanges(tt.netshOutput)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedRanges, ranges)
			}
		})
	}
}

func TestNewPKCEAuthorizationFlow_WithActualExcludedPorts(t *testing.T) {
	ranges := getSystemExcludedPortRanges()
	t.Logf("Found %d excluded port ranges on this system", len(ranges))

	listener1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		_ = listener1.Close()
	}()
	usedPort1 := listener1.Addr().(*net.TCPAddr).Port

	availablePort := 65432

	config := PKCEAuthProviderConfig{
		ClientID:              "test-client-id",
		Audience:              "test-audience",
		TokenEndpoint:         "https://test-token-endpoint.com/token",
		Scope:                 "openid email profile",
		AuthorizationEndpoint: "https://test-auth-endpoint.com/authorize",
		RedirectURLs: []string{
			fmt.Sprintf("http://127.0.0.1:%d/", usedPort1),
			fmt.Sprintf("http://127.0.0.1:%d/", availablePort),
		},
		UseIDToken: true,
	}

	flow, err := NewPKCEAuthorizationFlow(config)
	require.NoError(t, err)
	require.NotNil(t, flow)
	assert.Contains(t, flow.oAuthConfig.RedirectURL, fmt.Sprintf(":%d", availablePort),
		"Should skip port in use and select available port")
}
