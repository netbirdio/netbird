package idp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

type mockKeycloakCredentials struct {
	token JWTToken
	err   error
}

func (m *mockKeycloakCredentials) Authenticate(_ context.Context) (JWTToken, error) {
	return m.token, m.err
}

// capturingHTTPClient records the URL of every request it receives and
// answers with a fixed status/body, without making a real network call.
type capturingHTTPClient struct {
	code       int
	resBody    string
	requestURL string
}

func (c *capturingHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.requestURL = req.URL.String()
	return &http.Response{
		StatusCode: c.code,
		Body:       io.NopCloser(strings.NewReader(c.resBody)),
	}, nil
}

// TestKeycloakManager_AdminEndpointTrailingSlash reproduces netbirdio/netbird#4979:
// a trailing slash in the configured AdminEndpoint (e.g. because the realm name
// requires special handling, or simply an operator convention) produces a
// double slash in admin API request paths such as
// ".../admin/realms/<realm>//users/count". Keycloak >= 26.4.3 requires
// normalised paths and rejects the double slash with a 400, breaking
// authentication entirely.
func TestKeycloakManager_AdminEndpointTrailingSlash(t *testing.T) {
	km, err := NewKeycloakManager(KeycloakClientConfig{
		ClientID:      "client_id",
		ClientSecret:  "client_secret",
		AdminEndpoint: "https://id.example.com/admin/realms/test123/",
		TokenEndpoint: "https://id.example.com/realms/test123/protocol/openid-connect/token",
		GrantType:     "client_credentials",
	}, &telemetry.MockAppMetrics{})
	require.NoError(t, err)

	httpClient := &capturingHTTPClient{code: http.StatusOK, resBody: "3"}
	km.httpClient = httpClient
	km.credentials = &mockKeycloakCredentials{token: JWTToken{AccessToken: "token"}}

	_, err = km.totalUsersCount(context.Background())
	require.NoError(t, err)

	require.NotContains(t, httpClient.requestURL, "//users",
		"admin endpoint with a trailing slash must not produce a double slash in the request path: got %s", httpClient.requestURL)
}
