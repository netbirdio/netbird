package mcpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
)

var toolNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func TestCatalogBuildsValidTools(t *testing.T) {
	seen := map[string]bool{}
	for _, op := range catalog {
		tool, err := op.tool()
		require.NoError(t, err, op.name)
		assert.Regexp(t, toolNamePattern, tool.Name)
		assert.False(t, seen[tool.Name], "tool %s is defined twice", tool.Name)
		seen[tool.Name] = true
		assert.NotEmpty(t, tool.Description, "tool %s needs a description", tool.Name)
		assert.Equal(t, op.method == http.MethodGet, tool.Annotations.ReadOnlyHint, "read-only hint of %s", tool.Name)
		assert.Equal(t, op.method == http.MethodDelete || op.method == http.MethodPut, *tool.Annotations.DestructiveHint, "destructive hint of %s", tool.Name)
		_, err = op.resolvedSchema()
		assert.NoError(t, err, "the input schema of %s resolves for validation", tool.Name)
		assert.Equal(t, op.method != http.MethodPost, tool.Annotations.IdempotentHint, "idempotent hint of %s", tool.Name)

		// Every schema must marshal into a JSON object, which is what tools/list sends to clients.
		encoded, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err, op.name)
		var decoded map[string]any
		require.NoError(t, json.Unmarshal(encoded, &decoded), op.name)
		assert.Equal(t, "object", decoded["type"], "schema type of %s", tool.Name)
		assert.LessOrEqual(t, len(tool.Description), maxDescriptionLength, "description of %s is cut off by clients", tool.Name)
	}
}

// maxDescriptionLength is how much of a tool description Claude Code passes to the model.
const maxDescriptionLength = 4096

var toolMention = regexp.MustCompile(`\b(?:list|get|create|update|delete|approve|reject)_[a-z][a-z_]*\b`)

// TestGuidanceNamesExistingTools keeps descriptions and instructions from sending the
// model to a tool that does not exist.
func TestGuidanceNamesExistingTools(t *testing.T) {
	known := map[string]bool{}
	for _, op := range catalog {
		known[op.name] = true
	}
	check := func(source, text string) {
		for _, name := range toolMention.FindAllString(text, -1) {
			assert.True(t, known[name], "%s names unknown tool %s", source, name)
		}
	}
	for _, op := range catalog {
		check("description of "+op.name, op.description)
	}
	check("instructions", instructions)
	assert.LessOrEqual(t, len(instructions), 2048, "clients cut long server instructions")
}

func TestInputSchemaMergesPathQueryAndBody(t *testing.T) {
	op := findOperation(t, "update_peer")
	schema, err := op.inputSchema()
	require.NoError(t, err)

	assert.Equal(t, "string", schema.Properties["peer_id"].Type, "path argument is a string")
	assert.Equal(t, "string", schema.Properties["name"].Type, "body field is merged in")
	assert.Equal(t, "boolean", schema.Properties["ssh_enabled"].Type, "body field keeps its type")
	assert.Contains(t, schema.Properties, "ip", "optional body field is present")
	assert.Equal(t, "peer_id", schema.PropertyOrder[0], "path arguments come first")

	assert.Subset(t, schema.Required, []string{"peer_id", "name", "ssh_enabled", "login_expiration_enabled", "inactivity_expiration_enabled"})
	assert.NotContains(t, schema.Required, "ip", "pointer fields are optional")
	require.NotNil(t, schema.AdditionalProperties)
	assert.NotNil(t, schema.AdditionalProperties.Not, "unknown arguments are rejected by the schema")

	list := findOperation(t, "list_peers")
	listSchema, err := list.inputSchema()
	require.NoError(t, err)
	assert.Empty(t, listSchema.Required, "query arguments are optional")
	assert.ElementsMatch(t, []string{"name", "ip", "mac"}, listSchema.PropertyOrder)
}

func TestInputSchemaRejectsUndocumentedPathArgument(t *testing.T) {
	op := operation{name: "x", method: http.MethodGet, path: "/api/things/{thing_id}"}
	_, err := op.inputSchema()
	assert.ErrorContains(t, err, "thing_id")
}

func TestSelectOperations(t *testing.T) {
	all, err := selectOperations(nil)
	require.NoError(t, err)
	assert.Len(t, all, len(catalog), "empty allowlist exposes the whole catalog")

	selected, err := selectOperations([]string{"get_peer", "list_peers"})
	require.NoError(t, err)
	require.Len(t, selected, 2)
	assert.Equal(t, "list_peers", selected[0].name, "catalog order wins over allowlist order")
	assert.Equal(t, "get_peer", selected[1].name)

	_, err = selectOperations([]string{"list_peers", "list_unicorns"})
	assert.ErrorContains(t, err, "list_unicorns")
}

func TestOptionsFromEnv(t *testing.T) {
	t.Setenv(EnvTools, " list_peers, get_peer ,,")
	assert.Equal(t, []string{"list_peers", "get_peer"}, OptionsFromEnv().Tools)

	t.Setenv(EnvTools, "")
	assert.Empty(t, OptionsFromEnv().Tools)
}

func TestEnabledByEnv(t *testing.T) {
	t.Setenv(EnvEnabled, "")
	assert.False(t, EnabledByEnv(), "unset is off")
	t.Setenv(EnvEnabled, "true")
	assert.True(t, EnabledByEnv())
	t.Setenv(EnvEnabled, "yes please")
	assert.False(t, EnabledByEnv(), "unparseable is off")
}

// echo records what the REST router received so dispatch can be asserted on.
type echo struct {
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Vars   map[string]string `json:"vars"`
	Query  map[string]string `json:"query"`
	Body   json.RawMessage   `json:"body,omitempty"`
}

func echoRouter(t *testing.T) *mux.Router {
	t.Helper()
	router := mux.NewRouter()
	handler := func(w http.ResponseWriter, r *http.Request) {
		userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
		require.NoError(t, err, "dispatched request must carry the caller identity")
		query := map[string]string{}
		for name := range r.URL.Query() {
			query[name] = r.URL.Query().Get(name)
		}
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		w.Header().Set("X-Account", userAuth.AccountId)
		require.NoError(t, json.NewEncoder(w).Encode(echo{Method: r.Method, Path: r.URL.Path, Vars: mux.Vars(r), Query: query, Body: body}))
	}
	router.HandleFunc("/api/peers", handler).Methods(http.MethodGet)
	router.HandleFunc("/api/peers/{peerId}", handler).Methods(http.MethodGet, http.MethodPut)
	router.HandleFunc("/api/users", handler).Methods(http.MethodGet)
	router.HandleFunc("/api/accounts/{accountId}", handler).Methods(http.MethodPut)
	router.HandleFunc("/api/groups/{groupId}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"no delete for you","code":403}`))
	}).Methods(http.MethodDelete)
	router.HandleFunc("/api/dns/settings", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)
	return router
}

func authedContext() context.Context {
	return nbcontext.SetUserAuthInContext(context.Background(), auth.UserAuth{AccountId: "acc-1", UserId: "user-1"})
}

func call(t *testing.T, api http.Handler, tool string, args string) *mcp.CallToolResult {
	t.Helper()
	op := findOperation(t, tool)
	res, err := op.handler(api)(authedContext(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: tool, Arguments: json.RawMessage(args)}})
	require.NoError(t, err)
	require.NotNil(t, res)
	return res
}

func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	require.Len(t, res.Content, 1)
	text, ok := res.Content[0].(*mcp.TextContent)
	require.True(t, ok, "tool results are text")
	return text.Text
}

func echoOf(t *testing.T, res *mcp.CallToolResult) echo {
	t.Helper()
	require.False(t, res.IsError, textOf(t, res))
	var got echo
	require.NoError(t, json.Unmarshal([]byte(textOf(t, res)), &got))
	return got
}

func TestDispatchSplitsArgumentsIntoPathQueryAndBody(t *testing.T) {
	api := echoRouter(t)

	got := echoOf(t, call(t, api, "update_peer", `{"peer_id":"p 1","name":"laptop","ssh_enabled":true,"login_expiration_enabled":false,"inactivity_expiration_enabled":false}`))
	assert.Equal(t, http.MethodPut, got.Method)
	assert.Equal(t, "/api/peers/p 1", got.Path, "path argument is escaped on the wire and decoded by the router")
	assert.Equal(t, "p 1", got.Vars["peerId"])
	assert.JSONEq(t, `{"name":"laptop","ssh_enabled":true,"login_expiration_enabled":false,"inactivity_expiration_enabled":false}`, string(got.Body), "path argument stays out of the body")
	assert.Empty(t, got.Query)

	got = echoOf(t, call(t, api, "list_peers", `{"name":"laptop","ip":null}`))
	assert.Equal(t, http.MethodGet, got.Method)
	assert.Equal(t, map[string]string{"name": "laptop"}, got.Query, "null query arguments are dropped")
	assert.Empty(t, got.Body, "GET sends no body")

	got = echoOf(t, call(t, api, "list_users", `{"service_user":true}`))
	assert.Equal(t, map[string]string{"service_user": "true"}, got.Query, "booleans become query strings")
}

func TestDispatchRejectsBadArguments(t *testing.T) {
	api := echoRouter(t)

	res := call(t, api, "get_peer", `{}`)
	assert.True(t, res.IsError)
	assert.Contains(t, textOf(t, res), `missing properties: ["peer_id"]`)

	res = call(t, api, "get_peer", `{"peer_id":"p1","colour":"blue"}`)
	assert.True(t, res.IsError)
	assert.Contains(t, textOf(t, res), `unexpected additional properties ["colour"]`)

	res = call(t, api, "get_peer", `{"peer_id":{"nested":true}}`)
	assert.True(t, res.IsError)
	assert.Contains(t, textOf(t, res), `want "string"`)

	res = call(t, api, "list_peers", `[1,2]`)
	assert.True(t, res.IsError)
	assert.Contains(t, textOf(t, res), `want "object"`)
}

// TestDispatchValidatesBodyFields covers the case validation exists for: a body field the
// model misspells or leaves out must fail the call, not reach an update as a zero value.
func TestDispatchValidatesBodyFields(t *testing.T) {
	api := echoRouter(t)

	res := call(t, api, "update_peer", `{"peer_id":"p1","name":"web","ssh_enabled":false,"login_expiration_enabled":true}`)
	assert.True(t, res.IsError, "a missing required body field fails the call")
	assert.Contains(t, textOf(t, res), "inactivity_expiration_enabled")

	res = call(t, api, "update_peer", `{"peer_id":"p1","name":"web","ssh_enabled":false,"login_expiration_enabled":true,"inactivity_expiration_enabled":false,"ssh_enable":true}`)
	assert.True(t, res.IsError, "a misspelled field fails the call")
	assert.Contains(t, textOf(t, res), "ssh_enable")

	res = call(t, api, "update_peer", `{"peer_id":"p1","name":"web","ssh_enabled":"no","login_expiration_enabled":true,"inactivity_expiration_enabled":false}`)
	assert.True(t, res.IsError, "a wrongly typed field fails the call")

	res = call(t, api, "update_peer", `{"peer_id":"p1","name":"web","ssh_enabled":false,"login_expiration_enabled":true,"inactivity_expiration_enabled":false}`)
	assert.False(t, res.IsError, textOf(t, res))

	res = call(t, api, "update_account", `{"settings":{"peer_login_expiration_enabld":true}}`)
	assert.True(t, res.IsError, "a misspelled field inside a nested object fails the call too")
	assert.Contains(t, textOf(t, res), "peer_login_expiration_enabld")

	res = call(t, api, "list_peers", `null`)
	assert.False(t, res.IsError, "null arguments mean none: %s", textOf(t, res))

	res = call(t, api, "list_peers", `{"name":1,"ip":null}`)
	assert.False(t, res.IsError, "query arguments accept numbers and null: %s", textOf(t, res))
}

func TestDispatchBindsTheAccountToTheCaller(t *testing.T) {
	api := echoRouter(t)

	settings := `{"peer_expose_enabled":false,"peer_expose_groups":[],"peer_inactivity_expiration":0,` +
		`"peer_inactivity_expiration_enabled":false,"peer_login_expiration":86400,` +
		`"peer_login_expiration_enabled":true,"regular_users_view_blocked":true}`
	got := echoOf(t, call(t, api, "update_account", `{"settings":`+settings+`}`))
	assert.Equal(t, "/api/accounts/acc-1", got.Path, "the tool acts on the account the request is authenticated for")

	res := call(t, api, "update_account", `{"account_id":"acc-2","settings":`+settings+`}`)
	require.True(t, res.IsError, "an account the client names is refused, not dispatched")
	assert.Contains(t, textOf(t, res), "account_id")

	schema, err := findOperation(t, "update_account").inputSchema()
	require.NoError(t, err)
	assert.NotContains(t, schema.Properties, "account_id", "clients are not offered the argument")
}

func TestDispatchReportsAPIErrorsAsToolErrors(t *testing.T) {
	api := echoRouter(t)

	res := call(t, api, "delete_group", `{"group_id":"g1"}`)
	assert.True(t, res.IsError)
	assert.Contains(t, textOf(t, res), "delete_group failed with HTTP 403")
	assert.Contains(t, textOf(t, res), "no delete for you")

	res = call(t, api, "get_dns_settings", `{}`)
	assert.False(t, res.IsError)
	assert.Contains(t, textOf(t, res), "no content")

	res = call(t, api, "get_group", `{"group_id":"g1"}`)
	assert.True(t, res.IsError, "unrouted operations surface the router's 404/405")
}

func TestDispatchHonoursReadOnlyScope(t *testing.T) {
	api := echoRouter(t)
	readOnly := context.WithValue(authedContext(), scopesKey{}, []string{scopeRead})
	call := func(ctx context.Context, tool, args string) *mcp.CallToolResult {
		res, err := findOperation(t, tool).handler(api)(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: tool, Arguments: json.RawMessage(args)}})
		require.NoError(t, err)
		return res
	}

	res := call(readOnly, "update_peer", `{"peer_id":"p1","name":"x","ssh_enabled":false,"login_expiration_enabled":false,"inactivity_expiration_enabled":false}`)
	assert.True(t, res.IsError, "a read-only connection cannot change data")
	assert.Contains(t, textOf(t, res), "authorized to read only")

	res = call(readOnly, "get_peer", `{"peer_id":"p1"}`)
	assert.False(t, res.IsError, "reads still work")

	readWrite := context.WithValue(authedContext(), scopesKey{}, []string{scopeRead, scopeWrite})
	res = call(readWrite, "update_peer", `{"peer_id":"p1","name":"x","ssh_enabled":false,"login_expiration_enabled":false,"inactivity_expiration_enabled":false}`)
	assert.False(t, res.IsError, textOf(t, res))
}

func TestDispatchContainsHandlerPanics(t *testing.T) {
	panicking := mux.NewRouter()
	panicking.HandleFunc("/api/peers", func(http.ResponseWriter, *http.Request) {
		panic("handler bug")
	}).Methods(http.MethodGet)

	res := call(t, panicking, "list_peers", `{}`)
	assert.True(t, res.IsError, "a panicking handler fails the call")
	assert.Contains(t, textOf(t, res), "internal error")
}

func TestDispatchKeepsPathArgumentsToOneSegment(t *testing.T) {
	api := echoRouter(t)
	// A route the catalog does not map, one segment below get_peer's. The router matches on
	// the decoded path, so an escaped slash in peer_id would land here.
	reached := false
	api.HandleFunc("/api/peers/{peerId}/edr/bypass", func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)

	for _, id := range []string{"p1/edr/bypass", `p1\edr`, "..", "."} {
		encoded, err := json.Marshal(id)
		require.NoError(t, err)
		res := call(t, api, "get_peer", `{"peer_id":`+string(encoded)+`}`)
		assert.True(t, res.IsError, "peer_id %q is refused", id)
	}
	assert.False(t, reached, "no peer_id reaches a route outside the catalog")
	assert.Equal(t, "/api/peers/auth0|abc", echoOf(t, call(t, api, "get_peer", `{"peer_id":"auth0|abc"}`)).Path,
		"IDs with other punctuation still work")
}

func TestDispatchRefusesWithoutCallerIdentity(t *testing.T) {
	op := findOperation(t, "list_peers")
	_, err := op.handler(echoRouter(t))(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: op.name}})
	assert.ErrorContains(t, err, "caller identity missing")
}

// tokenTransport plays the MCP client's configured credential.
type tokenTransport struct {
	token string
}

func (t tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if t.token != "" {
		r.Header.Set("Authorization", "Bearer "+t.token)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// TestServeOverHTTP runs the real streamable transport end to end: the SDK
// client lists and calls tools against the mounted endpoint, behind a stand-in
// for the API auth middleware that puts the caller identity in the context.
func TestServeOverHTTP(t *testing.T) {
	root := mux.NewRouter()
	root.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer good" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, nbcontext.SetUserAuthInRequest(r, auth.UserAuth{AccountId: "acc-1", UserId: "user-1"}))
		})
	})
	require.NoError(t, RegisterEndpoints(root.PathPrefix("/api").Subrouter(), echoRouter(t), Options{Tools: []string{"get_peer", "list_peers"}}))

	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)
	ctx := context.Background()

	connect := func(token string) (*mcp.ClientSession, error) {
		client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
		return client.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   srv.URL + "/api" + Path,
			HTTPClient: &http.Client{Transport: tokenTransport{token: token}},
		}, nil)
	}

	_, err := connect("")
	assert.Error(t, err, "the endpoint sits behind the API authentication")

	tenant := func(account string) error {
		client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
		s, err := client.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   srv.URL + "/api" + Path + "?account=" + account,
			HTTPClient: &http.Client{Transport: tokenTransport{token: "good"}},
		}, nil)
		if err == nil {
			_ = s.Close()
		}
		return err
	}
	assert.Error(t, tenant("acc-2"), "an account the credential did not switch to is refused, not replaced by its own")
	assert.NoError(t, tenant("acc-1"), "the account the request runs as is served")
	for _, raw := range []string{"acc-2%", "acc-2;x=1", ""} {
		assert.Error(t, tenant(raw), "a tenant URL the middleware cannot read is refused: %q", raw)
	}
	miscased, err := (&http.Client{Transport: tokenTransport{token: "good"}}).Post(srv.URL+"/api"+Path+"?Account=acc-2", "application/json", strings.NewReader(`{}`))
	require.NoError(t, err)
	_ = miscased.Body.Close()
	assert.Equal(t, http.StatusBadRequest, miscased.StatusCode, "a miscased account key is refused, not ignored")

	session, err := connect("good")
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	tools, err := session.ListTools(ctx, nil)
	require.NoError(t, err)
	names := make([]string, 0, len(tools.Tools))
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	assert.ElementsMatch(t, []string{"list_peers", "get_peer"}, names, "only the allowlisted tools are advertised")

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_peer", Arguments: map[string]any{"peer_id": "p1"}})
	require.NoError(t, err)
	got := echoOf(t, res)
	assert.Equal(t, "/api/peers/p1", got.Path)
	assert.Equal(t, "p1", got.Vars["peerId"], "the caller identity from the HTTP request reaches the REST handler")

	res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "get_peer", Arguments: map[string]any{}})
	require.NoError(t, err)
	assert.True(t, res.IsError, "argument errors are tool errors, not transport errors")

	// A batch would run many tool calls for a single rate-limited HTTP request.
	batch := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_peer","arguments":{"peer_id":"p1"}}},` +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_peer","arguments":{"peer_id":"p2"}}}]`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api"+Path, strings.NewReader(batch))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := (&http.Client{Transport: tokenTransport{token: "good"}}).Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "JSON-RPC batches are refused")
}

func findOperation(t *testing.T, name string) operation {
	t.Helper()
	for _, op := range catalog {
		if op.name == name {
			return op
		}
	}
	t.Fatalf("operation %q is not in the catalog", name)
	return operation{}
}
