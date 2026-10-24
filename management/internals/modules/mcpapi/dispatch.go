package mcpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	log "github.com/sirupsen/logrus"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
)

// handler serves the operation by replaying the tool call as an in-process
// request against the REST API router. Argument mistakes come back as tool
// errors so the model can correct them; a missing caller identity is a
// deployment error and is reported as a protocol error instead.
func (o operation) handler(api http.Handler) mcp.ToolHandler {
	schema, schemaErr := o.resolvedSchema()
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if _, err := nbcontext.GetUserAuthFromContext(ctx); err != nil {
			return nil, fmt.Errorf("caller identity missing from request context: %w", err)
		}
		if !o.readOnly && !writeAllowed(ctx) {
			return toolError(fmt.Sprintf("%s changes data, but this connection was authorized to read only. "+
				"Sign in to the server again and allow changes to use it.", o.name)), nil
		}
		if schemaErr != nil {
			return nil, fmt.Errorf("input schema of %s: %w", o.name, schemaErr)
		}
		// The SDK does not validate the arguments of tools added with Server.AddTool. Without
		// this, a misspelled or missing field would reach the REST handler as its zero value,
		// and update tools would store it.
		if err := validateArguments(schema, req.Params.Arguments); err != nil {
			return toolError(err.Error()), nil
		}

		httpReq, err := o.buildRequest(ctx, req.Params.Arguments)
		if err != nil {
			return toolError(err.Error()), nil
		}

		rec := &responseRecorder{header: http.Header{}}
		if !serveContained(api, rec, httpReq) {
			return toolError(fmt.Sprintf("%s failed with an internal error", o.name)), nil
		}
		return o.result(rec), nil
	}
}

// serveContained runs the REST handler and reports whether it returned normally. The MCP
// SDK calls tool handlers on goroutines it starts itself, outside net/http's per-connection
// recovery, so a panicking handler would otherwise take the whole process down.
func serveContained(api http.Handler, rec *responseRecorder, req *http.Request) (ok bool) {
	defer func() {
		if p := recover(); p != nil {
			log.WithContext(req.Context()).Errorf("panic serving %s %s for an MCP tool call: %v\n%s", req.Method, req.URL.Path, p, debug.Stack())
			ok = false
		}
	}()
	api.ServeHTTP(rec, req)
	return true
}

func (o operation) resolvedSchema() (*jsonschema.Resolved, error) {
	schema, err := o.inputSchema()
	if err != nil {
		return nil, err
	}
	return schema.Resolve(nil)
}

func validateArguments(schema *jsonschema.Resolved, raw json.RawMessage) error {
	var args any = map[string]any{}
	// Absent and null arguments both mean none, as buildRequest and the SDK treat them.
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
		if err := json.Unmarshal(trimmed, &args); err != nil {
			return fmt.Errorf("arguments must be a JSON object: %w", err)
		}
	}
	if err := schema.Validate(args); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

// pathArgument is the value of a path argument: the caller's own for a caller-bound one,
// otherwise the client's.
func (o operation) pathArgument(ctx context.Context, args map[string]json.RawMessage, name string) (string, error) {
	bind, bound := callerBound[name]
	if !bound {
		return scalarArgument(args, name)
	}
	userAuth, err := nbcontext.GetUserAuthFromContext(ctx)
	if err != nil {
		return "", fmt.Errorf("caller identity missing from request context: %w", err)
	}
	return bind(userAuth), nil
}

// buildRequest splits the flat argument object into path, query and body and
// assembles the REST request that the catalog maps the tool onto.
func (o operation) buildRequest(ctx context.Context, raw json.RawMessage) (*http.Request, error) {
	args := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("arguments must be a JSON object: %w", err)
		}
	}

	path := o.path
	for _, name := range o.pathParams() {
		value, err := o.pathArgument(ctx, args, name)
		if err != nil {
			return nil, err
		}
		if value == "" {
			return nil, fmt.Errorf("missing required argument %q", name)
		}
		// The router matches on the decoded path, so an escaped slash would still split the
		// value into segments and reach a different route than the tool's.
		if strings.ContainsAny(value, "/\\") || value == "." || value == ".." {
			return nil, fmt.Errorf("argument %q must be a single ID, not a path", name)
		}
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(value))
		delete(args, name)
	}

	values := url.Values{}
	for _, q := range o.query {
		value, err := scalarArgument(args, q.name)
		if err != nil {
			return nil, err
		}
		if value != "" {
			values.Set(q.name, value)
		}
		delete(args, q.name)
	}

	var body io.Reader
	switch {
	case o.body != nil:
		encoded, err := json.Marshal(args)
		if err != nil {
			return nil, fmt.Errorf("encode request body: %w", err)
		}
		body = bytes.NewReader(encoded)
	case len(args) > 0:
		return nil, fmt.Errorf("unexpected arguments: %s", argumentNames(args))
	}

	target := path
	if len(values) > 0 {
		target += "?" + values.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, o.method, target, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body == nil {
		// Handlers run as if behind the HTTP server, which never hands them a nil body.
		req.Body = http.NoBody
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// scalarArgument returns the argument as the string the REST API expects in a
// URL. Numbers and booleans pass through as their JSON text; null and absent
// both mean "not given".
func scalarArgument(args map[string]json.RawMessage, name string) (string, error) {
	raw, ok := args[name]
	if !ok || string(bytes.TrimSpace(raw)) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("argument %q: %w", name, err)
	}
	switch v.(type) {
	case float64, bool:
		return string(bytes.TrimSpace(raw)), nil
	default:
		return "", fmt.Errorf("argument %q must be a string, number or boolean", name)
	}
}

// result turns the recorded REST response into the tool result. Non-2xx
// responses become tool errors carrying the API's error body, which already
// explains what was wrong (permission denied, validation, not found).
func (o operation) result(rec *responseRecorder) *mcp.CallToolResult {
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	text := strings.TrimSpace(rec.body.String())
	if status < 200 || status >= 300 {
		return toolError(fmt.Sprintf("%s failed with HTTP %d: %s", o.name, status, text))
	}
	if text == "" {
		text = fmt.Sprintf("%s succeeded with HTTP %d and no content", o.name, status)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func toolError(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: message}}}
}

// responseRecorder captures the REST handler's response in memory.
type responseRecorder struct {
	status int
	header http.Header
	body   bytes.Buffer
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

// argumentNames lists the argument names sorted, for stable error messages.
func argumentNames(args map[string]json.RawMessage) string {
	names := make([]string, 0, len(args))
	for name := range args {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
