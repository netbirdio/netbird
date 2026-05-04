package auth

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mgm "github.com/netbirdio/netbird/shared/management/client/common"
)

func TestPromptLogin(t *testing.T) {
	const (
		promptLogin = "prompt=login"
		maxAge0     = "max_age=0"
	)

	tt := []struct {
		name               string
		loginFlag          mgm.LoginFlag
		disablePromptLogin bool
		expectContains     []string
	}{
		{
			name:           "Prompt login",
			loginFlag:      mgm.LoginFlagPromptLogin,
			expectContains: []string{promptLogin},
		},
		{
			name:           "Max age 0",
			loginFlag:      mgm.LoginFlagMaxAge0,
			expectContains: []string{maxAge0},
		},
		{
			name:               "Disable prompt login",
			loginFlag:          mgm.LoginFlagPromptLogin,
			disablePromptLogin: true,
			expectContains:     []string{},
		},
		{
			name:           "None flag should not add parameters",
			loginFlag:      mgm.LoginFlagNone,
			expectContains: []string{},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			config := PKCEAuthProviderConfig{
				ClientID:              "test-client-id",
				Audience:              "test-audience",
				TokenEndpoint:         "https://test-token-endpoint.com/token",
				Scope:                 "openid email profile",
				AuthorizationEndpoint: "https://test-auth-endpoint.com/authorize",
				RedirectURLs:          []string{"http://127.0.0.1:33992/"},
				UseIDToken:            true,
				LoginFlag:             tc.loginFlag,
				DisablePromptLogin:    tc.disablePromptLogin,
			}
			pkce, err := NewPKCEAuthorizationFlow(config)
			if err != nil {
				t.Fatalf("Failed to create PKCEAuthorizationFlow: %v", err)
			}
			authInfo, err := pkce.RequestAuthInfo(context.Background())
			if err != nil {
				t.Fatalf("Failed to request auth info: %v", err)
			}

			for _, expected := range tc.expectContains {
				require.Contains(t, authInfo.VerificationURIComplete, expected)
			}
		})
	}
}

func TestIsPortInExcludedRange(t *testing.T) {
	tests := []struct {
		name            string
		port            string
		excludedRanges  []excludedPortRange
		expectedBlocked bool
	}{
		{
			name:            "Port in excluded range",
			port:            "8080",
			excludedRanges:  []excludedPortRange{{start: 8000, end: 8100}},
			expectedBlocked: true,
		},
		{
			name:            "Port at start of range",
			port:            "8000",
			excludedRanges:  []excludedPortRange{{start: 8000, end: 8100}},
			expectedBlocked: true,
		},
		{
			name:            "Port at end of range",
			port:            "8100",
			excludedRanges:  []excludedPortRange{{start: 8000, end: 8100}},
			expectedBlocked: true,
		},
		{
			name:            "Port before range",
			port:            "7999",
			excludedRanges:  []excludedPortRange{{start: 8000, end: 8100}},
			expectedBlocked: false,
		},
		{
			name:            "Port after range",
			port:            "8101",
			excludedRanges:  []excludedPortRange{{start: 8000, end: 8100}},
			expectedBlocked: false,
		},
		{
			name:            "Empty excluded ranges",
			port:            "8080",
			excludedRanges:  []excludedPortRange{},
			expectedBlocked: false,
		},
		{
			name:            "Nil excluded ranges",
			port:            "8080",
			excludedRanges:  nil,
			expectedBlocked: false,
		},
		{
			name: "Multiple ranges - port in second range",
			port: "9050",
			excludedRanges: []excludedPortRange{
				{start: 8000, end: 8100},
				{start: 9000, end: 9100},
			},
			expectedBlocked: true,
		},
		{
			name: "Multiple ranges - port not in any range",
			port: "8500",
			excludedRanges: []excludedPortRange{
				{start: 8000, end: 8100},
				{start: 9000, end: 9100},
			},
			expectedBlocked: false,
		},
		{
			name:            "Invalid port string",
			port:            "invalid",
			excludedRanges:  []excludedPortRange{{start: 8000, end: 8100}},
			expectedBlocked: false,
		},
		{
			name:            "Empty port string",
			port:            "",
			excludedRanges:  []excludedPortRange{{start: 8000, end: 8100}},
			expectedBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPortInExcludedRange(tt.port, tt.excludedRanges)
			assert.Equal(t, tt.expectedBlocked, result, "Port exclusion check mismatch")
		})
	}
}

func TestIsRedirectURLPortUsed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		_ = listener.Close()
	}()

	usedPort := listener.Addr().(*net.TCPAddr).Port

	tests := []struct {
		name           string
		redirectURL    string
		excludedRanges []excludedPortRange
		expectedUsed   bool
	}{
		{
			name:           "Port in excluded range",
			redirectURL:    "http://127.0.0.1:8080/",
			excludedRanges: []excludedPortRange{{start: 8000, end: 8100}},
			expectedUsed:   true,
		},
		{
			name:           "Port actually in use",
			redirectURL:    fmt.Sprintf("http://127.0.0.1:%d/", usedPort),
			excludedRanges: nil,
			expectedUsed:   true,
		},
		{
			name:           "Port not in use and not excluded",
			redirectURL:    "http://127.0.0.1:65432/",
			excludedRanges: nil,
			expectedUsed:   false,
		},
		{
			name:           "Invalid URL without port",
			redirectURL:    "not-a-valid-url",
			excludedRanges: nil,
			expectedUsed:   false,
		},
		{
			name:           "Port excluded even if not in use",
			redirectURL:    "http://127.0.0.1:8050/",
			excludedRanges: []excludedPortRange{{start: 8000, end: 8100}},
			expectedUsed:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRedirectURLPortUsed(tt.redirectURL, tt.excludedRanges)
			assert.Equal(t, tt.expectedUsed, result, "Port usage check mismatch")
		})
	}
}
