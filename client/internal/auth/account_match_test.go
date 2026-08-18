package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenInfoMatchesAccount(t *testing.T) {
	tests := []struct {
		name  string
		token TokenInfo
		hint  string
		match bool
	}{
		{
			name:  "same account",
			token: TokenInfo{Email: "user@example.com"},
			hint:  "user@example.com",
			match: true,
		},
		{
			name:  "different account",
			token: TokenInfo{Email: "other@example.com"},
			hint:  "user@example.com",
			match: false,
		},
		{
			name:  "case differences are the same account",
			token: TokenInfo{Email: "User@Example.com"},
			hint:  "user@example.com",
			match: true,
		},
		{
			name:  "no hint leaves the choice to the IdP",
			token: TokenInfo{Email: "other@example.com"},
			hint:  "",
			match: true,
		},
		{
			name:  "token without an email is not judged",
			token: TokenInfo{Email: ""},
			hint:  "user@example.com",
			match: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.match, tc.token.MatchesAccount(tc.hint))
		})
	}
}

func TestParseEmailFromIDToken(t *testing.T) {
	tests := []struct {
		name      string
		claims    map[string]interface{}
		wantValue string
		wantErr   bool
	}{
		{
			name:      "email claim",
			claims:    map[string]interface{}{"email": "user@example.com", "name": "Some One"},
			wantValue: "user@example.com",
		},
		{
			name:      "name fallback",
			claims:    map[string]interface{}{"name": "Some One"},
			wantValue: "Some One",
		},
		{
			name:    "neither claim present",
			claims:  map[string]interface{}{"sub": "abc"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			value, err := parseEmailFromIDToken(idTokenWithClaims(t, tc.claims))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantValue, value)
		})
	}
}

func TestRetryFlowForAccountUnsupportedFlow(t *testing.T) {
	assert.Nil(t, RetryFlowForAccount(&DeviceAuthorizationFlow{}))
}

func idTokenWithClaims(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}
