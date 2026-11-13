package grpc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestProxyOIDCConfig_OAuth2Config_ClientSecret(t *testing.T) {
	tests := []struct {
		name           string
		clientSecret   string
		expectedSecret string
	}{
		{name: "secret sent when configured", clientSecret: "s3cret", expectedSecret: "s3cret"},
		{name: "no secret for PKCE-only clients", clientSecret: "", expectedSecret: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotSecret, gotVerifier string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				gotSecret = r.PostForm.Get("client_secret")
				gotVerifier = r.PostForm.Get("code_verifier")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
			}))
			defer srv.Close()

			cfg := ProxyOIDCConfig{
				ClientID:     "client-id",
				ClientSecret: tc.clientSecret,
				CallbackURL:  "https://mgmt.example.com/callback",
			}.OAuth2Config(oauth2.Endpoint{TokenURL: srv.URL + "/token", AuthStyle: oauth2.AuthStyleInParams}, nil)

			verifier := oauth2.GenerateVerifier()
			_, err := cfg.Exchange(t.Context(), "code", oauth2.VerifierOption(verifier))
			require.NoError(t, err)

			assert.Equal(t, tc.expectedSecret, gotSecret, "client_secret sent to token endpoint")
			assert.Equal(t, verifier, gotVerifier, "PKCE verifier still sent")
		})
	}
}
