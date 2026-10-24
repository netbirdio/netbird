package mcpapi

import (
	"context"
	"encoding/json"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func callGuide(t *testing.T, args string) *mcp.CallToolResult {
	t.Helper()
	res, err := handleGuide(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: guideToolName, Arguments: json.RawMessage(args)}})
	require.NoError(t, err)
	return res
}

func TestGuidesAreServed(t *testing.T) {
	for _, g := range guides {
		res := callGuide(t, `{"topic":"`+g.topic+`"}`)
		require.False(t, res.IsError, "guide %s", g.topic)
		text := textOf(t, res)
		assert.True(t, strings.HasPrefix(text, "# "), "guide %s starts with its title", g.topic)
		assert.Less(t, len(text), 8000, "guide %s stays short enough to read in one call", g.topic)
	}

	assert.True(t, callGuide(t, `{"topic":"../server.go"}`).IsError, "only listed topics are served")
	assert.True(t, callGuide(t, `{}`).IsError)
	assert.True(t, callGuide(t, `[]`).IsError)
}

func TestEveryGuideFileIsListed(t *testing.T) {
	files, err := fs.Glob(guideFiles, "guides/*.md")
	require.NoError(t, err)
	listed := make([]string, 0, len(guides))
	for _, g := range guides {
		listed = append(listed, "guides/"+g.topic+".md")
	}
	assert.ElementsMatch(t, listed, files, "guide files and the guide list must match")
}

var toolMention = regexp.MustCompile(`\b(?:list|get|create|update|delete|approve|reject)_[a-z][a-z_]*\b`)

// TestGuidanceNamesExistingTools keeps the guides, descriptions and instructions from
// sending the model to a tool that does not exist.
func TestGuidanceNamesExistingTools(t *testing.T) {
	known := map[string]bool{guideToolName: true}
	for _, op := range catalog {
		known[op.name] = true
	}
	check := func(source, text string) {
		for _, name := range toolMention.FindAllString(text, -1) {
			assert.True(t, known[name], "%s names unknown tool %s", source, name)
		}
	}
	for _, g := range guides {
		body, err := guideFiles.ReadFile("guides/" + g.topic + ".md")
		require.NoError(t, err)
		check("guide "+g.topic, string(body))
	}
	for _, op := range catalog {
		check("description of "+op.name, op.description)
	}
	check("instructions", instructions)
	check("guide tool", guideTool().Description)
}

func TestGuideToolAndInstructionsFitClients(t *testing.T) {
	assert.LessOrEqual(t, len(guideTool().Description), maxDescriptionLength)
	assert.LessOrEqual(t, len(instructions), 2048, "clients cut long server instructions")
	for _, g := range guides {
		assert.Contains(t, instructions, g.topic, "the instructions point to guide %s", g.topic)
	}
}

func TestAllowlistKeepsTheGuides(t *testing.T) {
	selected, err := selectOperations([]string{"list_peers", guideToolName})
	require.NoError(t, err, "naming get_guide in the allowlist is not an error")
	require.Len(t, selected, 1)
	assert.Equal(t, "list_peers", selected[0].name)
}
