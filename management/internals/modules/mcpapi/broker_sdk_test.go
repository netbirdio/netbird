package mcpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGoSDKSignsIn drives the Go SDK's OAuth client against the broker: discovery, dynamic
// registration, PKCE, which the SDK refuses to sign in without, and the RFC 9207 issuer check.
func TestGoSDKSignsIn(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "ping"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "pong"}}}, nil, nil
	})
	endpoint := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	env := newBrokerEnvWith(t, httptest.NewServer, endpoint)

	fetcher := func(_ context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		browser := env.browser()
		resp, err := browser.Get(args.URL)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		m := requestField.FindStringSubmatch(string(body))
		require.Len(t, m, 2, "consent page: %d %s", resp.StatusCode, body)
		back := env.decide(browser, m[1], url.Values{"action": {"approve"}, "write": {"on"}}).Query()
		return &auth.AuthorizationResult{Code: back.Get("code"), State: back.Get("state"), Iss: back.Get("iss")}, nil
	}
	handler, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			ClientName:              "go-sdk",
			RedirectURIs:            []string{clientCallback},
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			TokenEndpointAuthMethod: "none",
		}},
		RedirectURL:              clientCallback,
		AuthorizationCodeFetcher: fetcher,
	})
	require.NoError(t, err)

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: env.srv.URL + "/api/mcp", OAuthHandler: handler}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	_, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "ping"})
	assert.NoError(t, err, "the token the SDK got is accepted")
}
