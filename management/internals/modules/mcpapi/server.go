package mcpapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/version"
)

const (
	// EnvTools is a comma-separated allowlist of tool names. Empty exposes the whole catalog.
	// get_guide makes no API call and is always exposed.
	EnvTools = "NB_MCP_TOOLS"

	serverName = "netbird-management"

	instructions = "Tools mirror the NetBird management REST API one-to-one and return its JSON. " +
		"IDs come from the list_* tools; pass IDs, never names. update_* tools replace the whole object: " +
		"fetch it first and send every field back, since an omitted field resets. " +
		"Errors carry the API's message; fix the arguments and retry rather than guessing.\n\n" +
		"Before a setup that takes several tools, call get_guide with one of: exit-nodes, site-to-site, " +
		"networks-and-dns, access-control, account-and-peers.\n\n" +
		"Model: groups hold peers and resources (a user's auto_groups apply to the user's peers), and " +
		"policies between groups are the only thing that lets traffic flow. The Default policy allows All to All until it is disabled. " +
		"Networks (network, resources, routers, and a policy to the resource groups) reach private hosts, " +
		"subnets and domains; routes (create_route) are deprecated except for exit nodes (0.0.0.0/0). " +
		"Settings on the device itself, such as netbird up flags, exit node selection or --allow-server-ssh, " +
		"cannot be changed here: tell the user what to run."
)

// Options configure which tools the endpoint exposes.
type Options struct {
	// Tools restricts the exposed tools to these names. Empty exposes the whole catalog.
	Tools []string
	// Usage counts tool calls for the self-hosted metrics. Nil counts nothing.
	Usage *Usage
}

// OptionsFromEnv reads the tool allowlist from NB_MCP_TOOLS.
func OptionsFromEnv() Options {
	var opts Options
	for _, name := range strings.Split(os.Getenv(EnvTools), ",") {
		if name = strings.TrimSpace(name); name != "" {
			opts.Tools = append(opts.Tools, name)
		}
	}
	return opts
}

// RegisterEndpoints mounts the MCP endpoint on router and serves every selected
// tool by dispatching to api, the REST API router. router must sit behind the
// API authentication middleware: tool calls take the caller identity from the
// request context and refuse to run without one.
func RegisterEndpoints(router, api *mux.Router, opts Options) error {
	server, err := newServer(api, opts)
	if err != nil {
		return err
	}

	// Stateless: every JSON-RPC message is its own HTTP request, so each tool
	// call is authenticated, rate limited and metered exactly like the REST
	// call it stands for, and no session state is kept on the server.
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
		// The SDK refuses a public Host on a loopback connection, against DNS rebinding of a
		// local server. Every call here carries its credential in a header, which a rebound
		// page cannot obtain, and a reverse proxy on the same host connects over loopback.
		DisableLocalhostProtection: true,
	})
	router.Handle(Path, requireTenant(rejectBatches(handler))).Methods(http.MethodPost, http.MethodGet, http.MethodDelete, http.MethodOptions)
	return nil
}

// rejectBatches refuses JSON-RPC batches before they reach the SDK. MCP dropped batching in
// 2025-06-18, and a batch would run many tool calls for a single rate-limited request.
func rejectBatches(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mcp.DefaultMaxRequestBodyBytes))
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		if trimmed := bytes.TrimLeft(body, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '[' {
			http.Error(w, "JSON-RPC batching is not supported", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

func newServer(api *mux.Router, opts Options) (*mcp.Server, error) {
	selected, err := selectOperations(opts.Tools)
	if err != nil {
		return nil, err
	}

	server := mcp.NewServer(
		&mcp.Implementation{Name: serverName, Title: serverTitle, Version: version.NetbirdVersion()},
		&mcp.ServerOptions{Instructions: instructions},
	)
	for _, op := range selected {
		tool, err := op.tool()
		if err != nil {
			return nil, fmt.Errorf("tool %s: %w", op.name, err)
		}
		server.AddTool(tool, counted(opts.Usage, op.handler(api)))
	}
	server.AddTool(guideTool(), counted(opts.Usage, handleGuide))
	return server, nil
}

// counted records each call of a tool in usage, attributed to the caller.
func counted(usage *Usage, handler mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if userAuth, err := nbcontext.GetUserAuthFromContext(ctx); err == nil {
			usage.record(userAuth.UserId, time.Now())
		}
		return handler(ctx, req)
	}
}

// selectOperations applies the allowlist to the catalog, keeping catalog order.
// An unknown name is an error so a typo in the deployment config fails boot
// instead of silently dropping a tool.
func selectOperations(names []string) ([]operation, error) {
	if len(names) == 0 {
		return catalog, nil
	}

	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		if name != guideToolName {
			wanted[name] = false
		}
	}
	selected := make([]operation, 0, len(names))
	for _, op := range catalog {
		if _, ok := wanted[op.name]; ok {
			wanted[op.name] = true
			selected = append(selected, op)
		}
	}
	for name, found := range wanted {
		if !found {
			return nil, fmt.Errorf("%s names unknown tool %q", EnvTools, name)
		}
	}
	return selected, nil
}

// Route is the REST operation behind one tool.
type Route struct {
	Tool   string
	Method string
	// Path carries the tool's path arguments in braces, e.g. "/api/peers/{peer_id}".
	Path string
}

// Routes lists the REST operation behind every tool in the catalog, so a
// deployment can check the catalog against the routes its API router serves.
func Routes() []Route {
	routes := make([]Route, 0, len(catalog))
	for _, op := range catalog {
		routes = append(routes, Route{Tool: op.name, Method: op.method, Path: op.path})
	}
	return routes
}

// requireTenant refuses an MCP request whose account query was not applied. A switching
// middleware leaves a request on the caller's own account when it cannot switch, for a typo,
// revoked access or a store error. Over a long-lived MCP URL every tool would then run against
// the wrong account without a word, so the endpoint fails closed instead.
func requireTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		// A query the middleware cannot read, an account key in another case or an empty
		// account is a mistyped tenant URL, which it would serve on the caller's own account.
		query, err := url.ParseQuery(r.URL.RawQuery)
		account := query.Get(accountParam)
		if err != nil || hasMiscasedAccount(query) || query.Has(accountParam) && account == "" {
			http.Error(w, "the account in the URL could not be read", http.StatusBadRequest)
			return
		}
		if account == "" {
			next.ServeHTTP(w, r)
			return
		}
		userAuth, err := nbcontext.GetUserAuthFromRequest(r)
		if err != nil || userAuth.AccountId != account {
			http.Error(w, "the account in the URL is not accessible with this credential", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hasMiscasedAccount(query url.Values) bool {
	for key := range query {
		if key != accountParam && strings.EqualFold(key, accountParam) {
			return true
		}
	}
	return false
}
