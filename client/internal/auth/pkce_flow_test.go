package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
)

func TestPromptLogin(t *testing.T) {
	tt := []struct {
		name   string
		prompt bool
	}{
		{"PromptLogin", true},
		{"NoPromptLogin", false},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			config := internal.PKCEAuthProviderConfig{
				ClientID:              "test-client-id",
				Audience:              "test-audience",
				TokenEndpoint:         "https://test-token-endpoint.com/token",
				Scope:                 "openid email profile",
				AuthorizationEndpoint: "https://test-auth-endpoint.com/authorize",
				RedirectURLs:          []string{"http://127.0.0.1:33992/"},
				UseIDToken:            true,
				DisablePromptLogin:    !tc.prompt,
			}
			pkce, err := NewPKCEAuthorizationFlow(config)
			if err != nil {
				t.Fatalf("Failed to create PKCEAuthorizationFlow: %v", err)
			}
			authInfo, err := pkce.RequestAuthInfo(context.Background())
			if err != nil {
				t.Fatalf("Failed to request auth info: %v", err)
			}
			pattern := "prompt=login"
			if tc.prompt {
				require.Contains(t, authInfo.VerificationURIComplete, pattern)
			} else {
				require.NotContains(t, authInfo.VerificationURIComplete, pattern)
			}
		})
	}
}
