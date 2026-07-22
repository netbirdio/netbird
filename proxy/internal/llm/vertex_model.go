package llm

import "strings"

// NormalizeVertexModel strips the "@version" suffix from a Vertex AI model id
// so it matches the catalog key, e.g. "claude-sonnet-4-5@20250929" ->
// "claude-sonnet-4-5". Shared by the parser, router, and guardrail so both
// spellings compare equal.
func NormalizeVertexModel(modelID string) string {
	if at := strings.Index(modelID, "@"); at >= 0 {
		return modelID[:at]
	}
	return modelID
}
