package mcpapi

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var pathParamPattern = regexp.MustCompile(`\{([a-z_]+)\}`)

// pathParams returns the brace names of the operation path, in order.
func (o operation) pathParams() []string {
	matches := pathParamPattern.FindAllStringSubmatch(o.path, -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m[1])
	}
	return names
}

// idempotent reports whether repeating the call has no further effect, which
// holds for every method the catalog uses except POST.
func (o operation) idempotent() bool {
	return o.method != http.MethodPost
}

// tool renders the operation as an MCP tool definition.
func (o operation) tool() (*mcp.Tool, error) {
	schema, err := o.inputSchema()
	if err != nil {
		return nil, err
	}
	destructive := o.destructive
	openWorld := false
	return &mcp.Tool{
		Name:        o.name,
		Title:       o.title,
		Description: o.description,
		InputSchema: schema,
		Annotations: &mcp.ToolAnnotations{
			Title:           o.title,
			ReadOnlyHint:    o.readOnly,
			DestructiveHint: &destructive,
			IdempotentHint:  o.idempotent(),
			OpenWorldHint:   &openWorld,
		},
	}, nil
}

// inputSchema builds one flat object schema for the tool: path arguments are
// required strings, query arguments optional strings, and the body type's
// properties are merged in at the top level so the model fills a single object.
func (o operation) inputSchema() (*jsonschema.Schema, error) {
	schema := &jsonschema.Schema{
		Type:                 "object",
		Properties:           map[string]*jsonschema.Schema{},
		AdditionalProperties: &jsonschema.Schema{Not: &jsonschema.Schema{}},
	}

	for _, name := range o.pathParams() {
		if name == callerBound {
			continue
		}
		description, ok := pathParamDescriptions[name]
		if !ok {
			return nil, fmt.Errorf("path argument %q has no description", name)
		}
		if err := addProperty(schema, name, &jsonschema.Schema{Type: "string", Description: description}); err != nil {
			return nil, err
		}
		schema.Required = append(schema.Required, name)
	}

	for _, q := range o.query {
		// Dispatch accepts numbers and booleans for query arguments as well, e.g. page: 1, and
		// treats null as omitted.
		if err := addProperty(schema, q.name, &jsonschema.Schema{Types: []string{"null", "string", "number", "boolean"}, Description: q.description}); err != nil {
			return nil, err
		}
	}

	if o.body == nil {
		return schema, nil
	}

	body, err := jsonschema.ForType(o.body, &jsonschema.ForOptions{IgnoreInvalidTypes: true})
	if err != nil {
		return nil, fmt.Errorf("schema for %s: %w", o.body, err)
	}
	if len(body.PropertyOrder) != len(body.Properties) {
		return nil, fmt.Errorf("schema for %s: property order lists %d of %d properties", o.body, len(body.PropertyOrder), len(body.Properties))
	}
	for _, name := range body.PropertyOrder {
		if err := addProperty(schema, name, body.Properties[name]); err != nil {
			return nil, err
		}
	}
	schema.Required = append(schema.Required, body.Required...)
	return schema, nil
}

func addProperty(schema *jsonschema.Schema, name string, property *jsonschema.Schema) error {
	if _, exists := schema.Properties[name]; exists {
		return fmt.Errorf("argument %q is defined twice", name)
	}
	schema.Properties[name] = property
	schema.PropertyOrder = append(schema.PropertyOrder, name)
	return nil
}
