package mcpapi

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/shared/management/client/common"
)

func testPKCEConfig() *nbconfig.Config {
	return &nbconfig.Config{
		HttpConfig: &nbconfig.HttpServerConfig{AuthIssuer: "https://idp.test/"},
		PKCEAuthorizationFlow: &nbconfig.PKCEAuthorizationFlow{ProviderConfig: nbconfig.ProviderConfig{
			ClientID:              "cli-client",
			ClientSecret:          "the-secret",
			Domain:                "idp.test",
			Audience:              "https://api.test/",
			AuthorizationEndpoint: "https://idp.test/authorize",
			TokenEndpoint:         "https://idp.test/oauth/token",
			Scope:                 "openid profile email offline_access",
			RedirectURLs:          []string{"http://localhost:53000/", "http://localhost:54000/"},
			UseIDToken:            true,
			LoginFlag:             common.LoginFlagPromptLogin,
		}},
	}
}

func TestFlowFromConfig(t *testing.T) {
	flow := FlowFromConfig(testPKCEConfig(), nil)
	require.NotNil(t, flow)
	assert.Equal(t, FlowConfig{
		ClientID:              "cli-client",
		Audience:              "https://api.test/",
		AuthorizationEndpoint: "https://idp.test/authorize",
		TokenEndpoint:         "https://idp.test/oauth/token",
		Scope:                 "openid profile email offline_access",
		UseIDToken:            true,
	}, *flow, "the configured PKCE flow")
	assert.Equal(t, "the-secret", FlowClientSecret(testPKCEConfig(), nil), "the broker gets the secret for confidential clients")

	assert.Nil(t, FlowFromConfig(&nbconfig.Config{}, nil), "no PKCE flow configured means no broker")
	assert.Nil(t, FlowFromConfig(nil, nil))
}

// embeddedProvider stands in for the embedded IdP; only the methods the flow reads are implemented.
type embeddedProvider struct {
	idp.OAuthConfigProvider
}

func (embeddedProvider) GetCLIClientID() string           { return "netbird-cli" }
func (embeddedProvider) GetAuthorizationEndpoint() string { return "https://mgmt.test/oauth2/auth" }
func (embeddedProvider) GetTokenEndpoint() string         { return "https://mgmt.test/oauth2/token" }
func (embeddedProvider) GetDefaultScopes() string         { return "openid profile email groups" }

func TestFlowFromConfigPrefersEmbeddedIdP(t *testing.T) {
	flow := FlowFromConfig(testPKCEConfig(), embeddedProvider{})
	require.NotNil(t, flow)
	assert.Equal(t, FlowConfig{
		ClientID:              "netbird-cli",
		Audience:              "netbird-cli",
		AuthorizationEndpoint: "https://mgmt.test/oauth2/auth",
		TokenEndpoint:         "https://mgmt.test/oauth2/token",
		Scope:                 "openid profile email groups",
	}, *flow, "the embedded IdP's public CLI client, with its client id as audience")
	assert.Empty(t, FlowClientSecret(testPKCEConfig(), embeddedProvider{}), "the embedded IdP's client is public")
}

func TestValidateRedirectURI(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:33418/", "http://[::1]:8080/cb", "http://localhost/callback", "https://claude.ai/api/mcp/auth_callback", "https://xn--pple-43d.com/cb"} {
		assert.NoError(t, validateRedirectURI(ok), ok)
	}
	for _, bad := range []string{"http://evil.example/cb", "cursor://anysphere.cursor-mcp/oauth/callback", "https://ok.example/cb#frag", "https://user@ok.example/cb", "/callback", "",
		"https://\u0430pple.com/cb", "https://%D0%B0pple.com/cb"} {
		assert.Error(t, validateRedirectURI(bad), bad)
	}
}

func TestRedirectAllowed(t *testing.T) {
	registered := []string{"http://localhost/callback", "http://127.0.0.1:33418/", "https://claude.ai/api/mcp/auth_callback"}

	assert.True(t, redirectAllowed(registered, "https://claude.ai/api/mcp/auth_callback"), "exact https match")
	assert.True(t, redirectAllowed(registered, "http://localhost:53123/callback"), "loopback matches on any port")
	assert.True(t, redirectAllowed(registered, "http://127.0.0.1:40000/"), "loopback IP matches on any port")

	assert.False(t, redirectAllowed(registered, "http://localhost:53123/other"), "loopback path must match")
	assert.False(t, redirectAllowed(registered, "http://127.0.0.1:40000/callback"), "loopback host must match the registration")
	assert.False(t, redirectAllowed(registered, "https://claude.ai/api/mcp/auth_callback/x"), "https needs an exact match")
	assert.False(t, redirectAllowed(registered, "https://claude.ai:8443/api/mcp/auth_callback"), "https port is not flexible")
	assert.False(t, redirectAllowed(registered, ""))
}

func TestResolveSecrets(t *testing.T) {
	oauthKey := strings.Repeat("k", minOAuthKeyLength)
	resolve := func(dataStoreKey string) Secrets {
		t.Helper()
		secrets, err := ResolveSecrets(dataStoreKey)
		require.NoError(t, err)
		return secrets
	}

	t.Setenv(EnvOAuthKey, oauthKey)
	assert.Equal(t, Secrets{Tokens: []byte(oauthKey), Registrations: []byte("datastore key")}, resolve("datastore key"),
		"the OAuth key rotates tokens on its own, registrations stay on the datastore key")
	assert.Equal(t, Secrets{Tokens: []byte(oauthKey), Registrations: []byte(oauthKey)}, resolve(""))

	t.Setenv(EnvOAuthKey, "short")
	_, err := ResolveSecrets("datastore key")
	assert.ErrorContains(t, err, EnvOAuthKey, "a short key is refused, not replaced by the datastore key")

	require.NoError(t, os.Unsetenv(EnvOAuthKey))
	assert.Equal(t, Secrets{Tokens: []byte("datastore key"), Registrations: []byte("datastore key")}, resolve("datastore key"))

	random := resolve("")
	assert.Len(t, random.Tokens, 32, "without either a random key is generated")
	assert.Equal(t, random.Tokens, random.Registrations)
}

func TestSealerSeparatesPurposes(t *testing.T) {
	s, err := newSealer([]byte("secret"))
	require.NoError(t, err)

	sealed, err := s.seal(purposeAccess, accessTokenPrefix, grant{Scopes: []string{scopeRead}})
	require.NoError(t, err)

	var g grant
	require.NoError(t, s.open(purposeAccess, accessTokenPrefix, sealed, &g))
	assert.Equal(t, []string{scopeRead}, g.Scopes)

	assert.Error(t, s.open(purposeRefresh, accessTokenPrefix, sealed, &g), "an access token is not a refresh token")
	assert.Error(t, s.open(purposeAccess, refreshTokenPrefix, sealed, &g), "the prefix is checked")
	assert.Error(t, s.open(purposeAccess, accessTokenPrefix, sealed[:len(sealed)-2]+"AA", &g), "tampering is detected")

	other, err := newSealer([]byte("another secret"))
	require.NoError(t, err)
	assert.Error(t, other.open(purposeAccess, accessTokenPrefix, sealed, &g), "another secret cannot open it")

	_, err = newSealer(nil)
	assert.Error(t, err)
}

func TestCallbackIsRegisteredWithTheEmbeddedIdP(t *testing.T) {
	assert.Equal(t, idp.MCPCallbackPath, apiPrefix+callbackPath,
		"the embedded IdP allows the callback the broker sends users back to")
}
