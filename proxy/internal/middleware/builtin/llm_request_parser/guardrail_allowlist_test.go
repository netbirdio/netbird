package llm_request_parser

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_guardrail"
)

// runParserGuardrail runs the request parser then the model-allowlist guardrail
// in SlotOnRequest order, threading the parser's metadata into the guardrail the
// same way the real chain does. It returns the guardrail decision so tests can
// assert allowlist enforcement for URL/path-routed providers end to end.
func runParserGuardrail(t *testing.T, url string, body []byte, allowlist []string) *middleware.Output {
	t.Helper()
	parser := newMiddleware(t)
	parsed, err := parser.Invoke(context.Background(), &middleware.Input{
		Slot: middleware.SlotOnRequest,
		URL:  url,
		Body: body,
	})
	require.NoError(t, err, "parser must not error")

	guard := llm_guardrail.New(llm_guardrail.Config{ModelAllowlist: allowlist})
	out, err := guard.Invoke(context.Background(), &middleware.Input{
		Slot:     middleware.SlotOnRequest,
		Metadata: parsed.Metadata,
	})
	require.NoError(t, err, "guardrail must not error")
	require.NotNil(t, out, "guardrail must return an output")
	return out
}

// TestModelAllowlist_URLRoutedProviders validates that the model allowlist is
// enforced for providers whose model travels in the URL path (AWS Bedrock,
// Google Vertex) rather than the JSON body. The "unknown action" case is the
// regression guard for #6751: a Bedrock request shape the parser cannot map to a
// model must fail closed under an allowlist instead of bypassing it.
func TestModelAllowlist_URLRoutedProviders(t *testing.T) {
	const bedrockBody = `{"anthropic_version":"bedrock-2023-05-31","messages":[{"role":"user","content":"hi"}]}`
	const vertexBody = `{"anthropic_version":"vertex-2023-10-16","messages":[{"role":"user","content":"hi"}]}`

	tests := []struct {
		name      string
		url       string
		body      string
		allowlist []string
		decision  middleware.Decision
		denyCode  string
	}{
		{
			name:      "bedrock allowed model passes",
			url:       "https://bedrock-runtime.us-east-1.amazonaws.com/model/us.anthropic.claude-haiku-4-5-v1:0/invoke",
			body:      bedrockBody,
			allowlist: []string{"anthropic.claude-haiku-4-5"},
			decision:  middleware.DecisionAllow,
		},
		{
			name:      "bedrock disallowed model denied",
			url:       "https://bedrock-runtime.us-east-1.amazonaws.com/model/us.anthropic.claude-opus-4-8-v1:0/invoke",
			body:      bedrockBody,
			allowlist: []string{"anthropic.claude-haiku-4-5"},
			decision:  middleware.DecisionDeny,
			denyCode:  "llm_policy.model_blocked",
		},
		{
			name:      "bedrock unknown action fails closed",
			url:       "https://bedrock-runtime.us-east-1.amazonaws.com/model/us.anthropic.claude-opus-4-8-v1:0/some-future-action",
			body:      bedrockBody,
			allowlist: []string{"anthropic.claude-haiku-4-5"},
			decision:  middleware.DecisionDeny,
			denyCode:  "llm_policy.model_unknown",
		},
		{
			name:      "vertex disallowed model denied",
			url:       "/v1/projects/p/locations/global/publishers/anthropic/models/claude-opus-4-8@20250101:rawPredict",
			body:      vertexBody,
			allowlist: []string{"claude-haiku-4-5"},
			decision:  middleware.DecisionDeny,
			denyCode:  "llm_policy.model_blocked",
		},
		{
			name:      "vertex allowed model passes",
			url:       "/v1/projects/p/locations/global/publishers/anthropic/models/claude-haiku-4-5@20250101:rawPredict",
			body:      vertexBody,
			allowlist: []string{"claude-haiku-4-5"},
			decision:  middleware.DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runParserGuardrail(t, tt.url, []byte(tt.body), tt.allowlist)
			assert.Equal(t, tt.decision, out.Decision, "unexpected decision for %s", tt.name)
			if tt.decision == middleware.DecisionDeny {
				require.NotNil(t, out.DenyReason, "deny reason must be set for %s", tt.name)
				assert.Equal(t, 403, out.DenyStatus, "deny status must be 403 for %s", tt.name)
				assert.Equal(t, tt.denyCode, out.DenyReason.Code, "deny code for %s", tt.name)
			}
		})
	}
}

// TestModelAllowlist_VertexRequestShapes replays the Vertex request shapes an
// Anthropic SDK client sends (model in the URL path, optionally unversioned,
// plus the count-tokens body-model endpoint) against bare and "@version"
// allowlists. URLs mirror a customer-reported request.
func TestModelAllowlist_VertexRequestShapes(t *testing.T) {
	const (
		opusBare      = "/v1/projects/corp-gcp-it-all-claude/locations/global/publishers/anthropic/models/claude-opus-4-6:rawPredict"
		opusBareSSE   = "/v1/projects/corp-gcp-it-all-claude/locations/global/publishers/anthropic/models/claude-opus-4-6:streamRawPredict"
		countTokens   = "/v1/projects/corp-gcp-it-all-claude/locations/global/publishers/anthropic/models/count-tokens:rawPredict"
		messagesBody  = `{"anthropic_version":"vertex-2023-10-16","messages":[{"role":"user","content":"hi"}]}`
		countOpusBody = `{"model":"claude-opus-4-6","messages":[{"role":"user","content":"hi"}]}`
	)

	tests := []struct {
		name      string
		url       string
		body      string
		allowlist []string
		decision  middleware.Decision
		denyCode  string
	}{
		{
			name:      "unversioned model allowed by bare catalog entry",
			url:       opusBare,
			body:      messagesBody,
			allowlist: []string{"claude-opus-4-6"},
			decision:  middleware.DecisionAllow,
		},
		{
			name:      "unversioned model allowed by @version allowlist entry",
			url:       opusBare,
			body:      messagesBody,
			allowlist: []string{"claude-opus-4-6@20250514"},
			decision:  middleware.DecisionAllow,
		},
		{
			name:      "streaming action allowed the same as rawPredict",
			url:       opusBareSSE,
			body:      messagesBody,
			allowlist: []string{"claude-opus-4-6"},
			decision:  middleware.DecisionAllow,
		},
		{
			// The customer report: a Sonnet-only allowlist must block Opus.
			name:      "unversioned model outside the allowlist denied",
			url:       opusBare,
			body:      messagesBody,
			allowlist: []string{"claude-sonnet-4-5"},
			decision:  middleware.DecisionDeny,
			denyCode:  "llm_policy.model_blocked",
		},
		{
			name:      "count-tokens resolves the body model and passes when allowed",
			url:       countTokens,
			body:      countOpusBody,
			allowlist: []string{"claude-opus-4-6"},
			decision:  middleware.DecisionAllow,
		},
		{
			name:      "count-tokens with a disallowed body model denied",
			url:       countTokens,
			body:      countOpusBody,
			allowlist: []string{"claude-sonnet-4-5"},
			decision:  middleware.DecisionDeny,
			denyCode:  "llm_policy.model_blocked",
		},
		{
			// No body model: the pseudo-model stays and fails closed.
			name:      "count-tokens without a body model fails closed",
			url:       countTokens,
			body:      messagesBody,
			allowlist: []string{"claude-opus-4-6"},
			decision:  middleware.DecisionDeny,
			denyCode:  "llm_policy.model_blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := runParserGuardrail(t, tt.url, []byte(tt.body), tt.allowlist)
			assert.Equal(t, tt.decision, out.Decision, "unexpected decision for %s", tt.name)
			if tt.decision == middleware.DecisionDeny {
				require.NotNil(t, out.DenyReason, "deny reason must be set for %s", tt.name)
				assert.Equal(t, 403, out.DenyStatus, "deny status must be 403 for %s", tt.name)
				assert.Equal(t, tt.denyCode, out.DenyReason.Code, "deny code for %s", tt.name)
			}
		})
	}
}
