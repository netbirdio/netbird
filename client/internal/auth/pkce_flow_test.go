package auth

import (
	"context"
	"testing"

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
		expect             string
	}{
		{
			name:      "Prompt login",
			loginFlag: mgm.LoginFlagPrompt,
			expect:    promptLogin,
		},
		{
			name:      "Max age 0 login",
			loginFlag: mgm.LoginFlagMaxAge0,
			expect:    maxAge0,
		},
		{
			name:               "Disable prompt login",
			loginFlag:          mgm.LoginFlagPrompt,
			disablePromptLogin: true,
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
			}
			pkce, err := NewPKCEAuthorizationFlow(config)
			if err != nil {
				t.Fatalf("Failed to create PKCEAuthorizationFlow: %v", err)
			}
			authInfo, err := pkce.RequestAuthInfo(context.Background())
			if err != nil {
				t.Fatalf("Failed to request auth info: %v", err)
			}

			if !tc.disablePromptLogin {
				require.Contains(t, authInfo.VerificationURIComplete, tc.expect)
			} else {
				require.Contains(t, authInfo.VerificationURIComplete, promptLogin)
				require.NotContains(t, authInfo.VerificationURIComplete, maxAge0)
			}
		})
	}
}
