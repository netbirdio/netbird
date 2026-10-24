package mcpapi

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// guideToolName serves the guides. It makes no API call, so it is always exposed.
const guideToolName = "get_guide"

//go:embed guides/*.md
var guideFiles embed.FS

// guide is a how-to for a setup that takes several tools in a set order, written from the
// NetBird documentation and checked against the API, for an agent to follow.
type guide struct {
	topic   string
	summary string
}

var guides = []guide{
	{"exit-nodes", "send a peer group's internet traffic through a routing peer (0.0.0.0/0 route), with HA, location gating and DNS."},
	{"site-to-site", "connect LANs or VPCs through routing peers with Networks or legacy routes, site-to-VPN, masquerade and overlapping subnets."},
	{"networks-and-dns", "reach private hosts, subnets and domains through Networks (resources, routers, policies) and configure nameservers, zones and records."},
	{"access-control", "least-privilege policies, replacing the Default policy, posture checks, NetBird SSH and verifying access."},
	{"account-and-peers", "account settings without resetting fields, peer approval, expiration and SSH, setup keys, users, roles and groups."},
}

func guideTopics() []any {
	topics := make([]any, 0, len(guides))
	for _, g := range guides {
		topics = append(topics, g.topic)
	}
	return topics
}

func guideTool() *mcp.Tool {
	var index strings.Builder
	index.WriteString("Read a step-by-step guide before configuring one of these setups. Topics:")
	for _, g := range guides {
		fmt.Fprintf(&index, "\n- %s: %s", g.topic, g.summary)
	}
	destructive, openWorld := false, false
	return &mcp.Tool{
		Name:        guideToolName,
		Title:       "Get guide",
		Description: index.String(),
		InputSchema: &jsonschema.Schema{
			Type:     "object",
			Required: []string{"topic"},
			Properties: map[string]*jsonschema.Schema{
				"topic": {Type: "string", Enum: guideTopics(), Description: "The guide to read."},
			},
			AdditionalProperties: &jsonschema.Schema{Not: &jsonschema.Schema{}},
		},
		Annotations: &mcp.ToolAnnotations{
			Title:           "Get guide",
			ReadOnlyHint:    true,
			DestructiveHint: &destructive,
			IdempotentHint:  true,
			OpenWorldHint:   &openWorld,
		},
	}
}

func handleGuide(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		Topic string `json:"topic"`
	}
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		return toolError(fmt.Sprintf("arguments must be an object with a topic: %v", err)), nil
	}
	for _, g := range guides {
		if g.topic != args.Topic {
			continue
		}
		body, err := guideFiles.ReadFile("guides/" + g.topic + ".md")
		if err != nil {
			return nil, fmt.Errorf("read guide %s: %w", g.topic, err)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil
	}
	return toolError(fmt.Sprintf("unknown topic %q; use one of the topics listed in the tool description", args.Topic)), nil
}
