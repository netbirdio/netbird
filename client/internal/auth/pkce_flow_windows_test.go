//go:build windows

package auth

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"

	"github.com/netbirdio/netbird/client/internal"
)

func TestNewPKCEAuthorizationFlow_ExcludedPorts(t *testing.T) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Skipf("Cannot open registry key (may need admin privileges): %v", err)
		return
	}
	defer func() {
		_ = k.Close()
	}()

	originalReservedPorts, _, err := k.GetStringsValue("ReservedPorts")
	if err != nil && err != registry.ErrNotExist {
		t.Skipf("Cannot read ReservedPorts from registry: %v", err)
		return
	}

	defer func() {
		if err == registry.ErrNotExist {
			_ = k.DeleteValue("ReservedPorts")
		} else {
			_ = k.SetStringsValue("ReservedPorts", originalReservedPorts)
		}
	}()

	testExcludedRanges := []string{
		"8080-8090",
		"9000-9010",
	}

	if err := k.SetStringsValue("ReservedPorts", testExcludedRanges); err != nil {
		t.Skipf("Cannot write ReservedPorts to registry (may need admin privileges): %v", err)
		return
	}

	listener1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		_ = listener1.Close()
	}()
	usedPort1 := listener1.Addr().(*net.TCPAddr).Port

	listener2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		_ = listener2.Close()
	}()
	usedPort2 := listener2.Addr().(*net.TCPAddr).Port

	availablePort := 65432

	tests := []struct {
		name         string
		redirectURLs []string
		expectError  bool
		expectedPort int
	}{
		{
			name: "Skip excluded port range, use next available",
			redirectURLs: []string{
				"http://127.0.0.1:8085/",
				fmt.Sprintf("http://127.0.0.1:%d/", availablePort),
			},
			expectError:  false,
			expectedPort: availablePort,
		},
		{
			name: "Skip multiple excluded ranges",
			redirectURLs: []string{
				"http://127.0.0.1:8082/",
				"http://127.0.0.1:9005/",
				fmt.Sprintf("http://127.0.0.1:%d/", availablePort),
			},
			expectError:  false,
			expectedPort: availablePort,
		},
		{
			name: "Skip port in use, use next available",
			redirectURLs: []string{
				fmt.Sprintf("http://127.0.0.1:%d/", usedPort1),
				fmt.Sprintf("http://127.0.0.1:%d/", availablePort),
			},
			expectError:  false,
			expectedPort: availablePort,
		},
		{
			name: "All ports excluded or in use",
			redirectURLs: []string{
				fmt.Sprintf("http://127.0.0.1:%d/", usedPort1),
				fmt.Sprintf("http://127.0.0.1:%d/", usedPort2),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := internal.PKCEAuthProviderConfig{
				ClientID:              "test-client-id",
				Audience:              "test-audience",
				TokenEndpoint:         "https://test-token-endpoint.com/token",
				Scope:                 "openid email profile",
				AuthorizationEndpoint: "https://test-auth-endpoint.com/authorize",
				RedirectURLs:          tt.redirectURLs,
				UseIDToken:            true,
			}

			flow, err := NewPKCEAuthorizationFlow(config)

			if tt.expectError {
				assert.Error(t, err, "Expected error when no ports available")
				assert.Nil(t, flow)
			} else {
				require.NoError(t, err)
				require.NotNil(t, flow)
				assert.Contains(t, flow.oAuthConfig.RedirectURL, fmt.Sprintf(":%d", tt.expectedPort))
			}
		})
	}
}
