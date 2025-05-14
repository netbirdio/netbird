package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestPromptLogin(t *testing.T) {
	const (
		promptLogin = "prompt=login"
		maxAge0     = "max_age=0"
	)

	tt := []struct {
		name      string
		loginFlag types.LoginFlag
		expect    string
	}{
		{
			name:      "Prompt login",
			loginFlag: types.LoginFlagPrompt,
			expect:    promptLogin,
		},
		{
			name:      "Max age 0 login",
			loginFlag: types.LoginFlagMaxAge0,
			expect:    maxAge0,
		},
		{
			name:      "Disabled additional login flags",
			loginFlag: types.LoginFlagDisabled,
		},
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
				LoginFlag:             tc.loginFlag,
			}
			pkce, err := NewPKCEAuthorizationFlow(config)
			if err != nil {
				t.Fatalf("Failed to create PKCEAuthorizationFlow: %v", err)
			}
			authInfo, err := pkce.RequestAuthInfo(context.Background())
			if err != nil {
				t.Fatalf("Failed to request auth info: %v", err)
			}

			if tc.loginFlag != types.LoginFlagDisabled {
				require.Contains(t, authInfo.VerificationURIComplete, tc.expect)
			} else {
				require.NotContains(t, authInfo.VerificationURIComplete, promptLogin)
				require.NotContains(t, authInfo.VerificationURIComplete, maxAge0)
			}
		})
	}
}
