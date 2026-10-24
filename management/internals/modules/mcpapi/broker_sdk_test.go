package mcpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// TestGoSDKSignsInAgainAfterKeyChange drives the Go SDK client through a change of the token
// key. The SDK only drops a token whose refresh fails with invalid_grant; any other error
// would leave it retrying the dead refresh token forever.
func TestGoSDKSignsInAgainAfterKeyChange(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "ping"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "pong"}}}, nil, nil
	})
	endpoint := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	env := newBrokerEnvWith(t, httptest.NewServer, endpoint)

	var mu sync.Mutex
	var logins int
	var current *oauth2.Token
	fetcher := func(_ context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		mu.Lock()
		logins++
		mu.Unlock()
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
		NewTokenSource: func(ctx context.Context, cfg *oauth2.Config, tok *oauth2.Token) (oauth2.TokenSource, error) {
			mu.Lock()
			current = tok
			mu.Unlock()
			return cfg.TokenSource(ctx, tok), nil
		},
	})
	require.NoError(t, err)

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: env.srv.URL + "/api/mcp", OAuthHandler: handler}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	_, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "ping"})
	require.NoError(t, err)

	rotated, err := newSealer([]byte("rotated secret"))
	require.NoError(t, err)
	env.broker.seal = rotated
	// The client's access token has also expired, so its next call starts with a refresh.
	mu.Lock()
	current.Expiry = time.Now().Add(-time.Hour)
	mu.Unlock()

	_, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "ping"})
	assert.NoError(t, err, "the client signs in again on its own")
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, logins, "one sign-in before the key change and one after")
}
