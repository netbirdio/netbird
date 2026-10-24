//go:build e2e

// Package mcpe2e is the container-based suite for the MCP endpoint and its OAuth
// broker. One combined server runs for the package with nothing set beyond
// NB_MCP_ENABLED, so the OAuth tests also prove that a self-hosted deployment with
// the embedded IdP needs no further configuration. Each test cleans up what it
// creates.
package mcpe2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	// mcpPath is the MCP endpoint, relative to the server's base URL.
	mcpPath = "/api/mcp"

	// initializeRequest is a complete MCP request. The endpoint is stateless and answers it
	// on its own, so posting it shows whether a credential is accepted without a client
	// library standing between the test and the status code.
	initializeRequest = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",` +
		`"capabilities":{},"clientInfo":{"name":"netbird-e2e","version":"0"}}}`

	// logTailLines bounds the server log printed for a failed test.
	logTailLines = 300
)

// srv is the shared combined server, PAT-authenticated by the time any test runs.
var srv *harness.Combined

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	// Generous timeout to cover a cold image build on first run.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	var err error
	srv, err = harness.StartCombined(ctx, harness.WithServerEnv(map[string]string{
		"NB_MCP_ENABLED": "true",
	}))
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: start combined server: %v\n", err)
		return 1
	}
	defer func() { _ = srv.Terminate(context.Background()) }()

	if _, err := srv.Bootstrap(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: bootstrap admin PAT: %v\n%s\n", err, srv.Logs(context.Background()))
		return 1
	}

	return m.Run()
}

// logsOnFailure prints the tail of the server log when the test fails. The suite's
// failures are mostly decided inside the server, where the log is the only witness.
func logsOnFailure(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		lines := strings.Split(srv.Logs(context.Background()), "\n")
		if len(lines) > logTailLines {
			lines = lines[len(lines)-logTailLines:]
		}
		t.Logf("=== combined server log (last %d lines) ===\n%s", len(lines), strings.Join(lines, "\n"))
	})
}

// authTransport sets the Authorization header on every request, the way an MCP client
// configured with a credential does.
type authTransport struct {
	base          http.RoundTripper
	authorization string
}

func (a authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", a.authorization)
	base := a.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}

// connect opens an MCP session at endpoint, authenticating every request with
// authorization and sending it through base (nil for the default transport).
func connect(ctx context.Context, t *testing.T, endpoint, authorization string, base http.RoundTripper) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "netbird-e2e", Version: "0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: &http.Client{Transport: authTransport{base: base, authorization: authorization}, Timeout: time.Minute},
	}, nil)
	require.NoError(t, err, "connect to %s", endpoint)
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// probe posts an initialize request to endpoint and returns the response status and
// headers. An empty authorization sends no credential.
func probe(ctx context.Context, t *testing.T, client *http.Client, endpoint, authorization string) (int, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(initializeRequest))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := client.Do(req)
	require.NoError(t, err, "POST %s", endpoint)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header
}

// toolNames lists every tool the session advertises, across pages.
func toolNames(ctx context.Context, t *testing.T, session *mcp.ClientSession) []string {
	t.Helper()
	var names []string
	for tool, err := range session.Tools(ctx, nil) {
		require.NoError(t, err, "list tools")
		names = append(names, tool.Name)
	}
	return names
}

// findTool returns the advertised definition of the named tool.
func findTool(ctx context.Context, t *testing.T, session *mcp.ClientSession, name string) *mcp.Tool {
	t.Helper()
	for tool, err := range session.Tools(ctx, nil) {
		require.NoError(t, err, "list tools")
		if tool.Name == name {
			return tool
		}
	}
	require.Failf(t, "tool not advertised", "%s is not in tools/list", name)
	return nil
}

// schemaProperties returns the property names of a tool's input schema.
func schemaProperties(t *testing.T, tool *mcp.Tool) []string {
	t.Helper()
	raw, err := json.Marshal(tool.InputSchema)
	require.NoError(t, err)
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(raw, &schema), "input schema of %s", tool.Name)
	names := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// callTool runs a tool and returns its result, failing the test on a protocol error.
// Tool errors come back in the result for the caller to assert on.
func callTool(ctx context.Context, t *testing.T, session *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	require.NoError(t, err, "call %s", name)
	return res
}

// resultText joins the text content of a tool result.
func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var parts []string
	for _, c := range res.Content {
		text, ok := c.(*mcp.TextContent)
		require.True(t, ok, "tool results carry text content, got %T", c)
		parts = append(parts, text.Text)
	}
	return strings.Join(parts, "\n")
}

// decodeResult requires a successful tool result and decodes its JSON text into out.
func decodeResult(t *testing.T, name string, res *mcp.CallToolResult, out any) {
	t.Helper()
	text := resultText(t, res)
	require.False(t, res.IsError, "%s failed: %s", name, text)
	require.NoError(t, json.Unmarshal([]byte(text), out), "%s returned: %s", name, text)
}

// uniqueName returns a resource name no other test run collides with.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// groupExists reports whether the REST API lists a group with the given ID.
func groupExists(ctx context.Context, t *testing.T, id string) bool {
	t.Helper()
	groups, err := srv.API().Groups.List(ctx)
	require.NoError(t, err, "list groups over REST")
	return slices.ContainsFunc(groups, func(g api.Group) bool { return g.Id == id })
}

// groupNamed returns the ID of the group with the given name, or "" when there is none.
func groupNamed(ctx context.Context, t *testing.T, name string) string {
	t.Helper()
	groups, err := srv.API().Groups.List(ctx)
	require.NoError(t, err, "list groups over REST")
	for _, g := range groups {
		if g.Name == name {
			return g.Id
		}
	}
	return ""
}

// deleteGroupIfPresent removes a group a test created, for cleanup after a failure part
// way through. A group the test already deleted is fine.
func deleteGroupIfPresent(t *testing.T, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if id == "" || !groupExists(ctx, t, id) {
		return
	}
	if err := srv.API().Groups.Delete(ctx, id); err != nil {
		t.Logf("cleanup: delete group %s: %v", id, err)
	}
}
