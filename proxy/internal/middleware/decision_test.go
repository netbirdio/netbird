package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeDeny renders a denial and returns the parsed body plus the status.
func decodeDeny(t *testing.T, reason *DenyReason, status int) (map[string]any, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	RenderDenyResponse(rec, "llm_limit_check", reason, status)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), "deny body must be valid JSON")
	return body, rec.Code
}

// TestRenderDeny_AnthropicSurfaceMirrorsVendorShape covers a budget stop
// reaching Claude Code. The client only parses the Anthropic envelope, so
// without the mirror the user sees an unexplained API error instead of the
// reason their request was refused.
func TestRenderDeny_AnthropicSurfaceMirrorsVendorShape(t *testing.T) {
	body, status := decodeDeny(t, &DenyReason{
		Code:    "llm_policy.budget_cap_exceeded",
		Message: "LLM policy limit exceeded",
		Surface: "anthropic",
	}, http.StatusForbidden)

	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "error", body["type"], "Anthropic errors carry type=error at the top level")

	errObj, ok := body["error"].(map[string]any)
	require.True(t, ok, "error must be an object")
	assert.Equal(t, "permission_error", errObj["type"], "403 maps to permission_error")
	assert.Equal(t, "LLM policy limit exceeded", errObj["message"])

	// The NetBird fields stay put so existing consumers keep working.
	assert.Equal(t, "llm_policy.budget_cap_exceeded", body["code"])
	assert.Equal(t, "LLM policy limit exceeded", body["message"])
	assert.Equal(t, "llm_limit_check", body["middleware"])
}

// TestRenderDeny_OpenAISurfaceMirrorsVendorShape pins the OpenAI envelope,
// which nests the code and carries no top-level type.
func TestRenderDeny_OpenAISurfaceMirrorsVendorShape(t *testing.T) {
	body, _ := decodeDeny(t, &DenyReason{
		Code:    "llm_policy.model_blocked",
		Message: "model is not in the policy allowlist",
		Surface: "openai",
	}, http.StatusForbidden)

	assert.NotContains(t, body, "type", "OpenAI errors have no top-level type")

	errObj, ok := body["error"].(map[string]any)
	require.True(t, ok, "error must be an object")
	assert.Equal(t, "invalid_request_error", errObj["type"])
	assert.Equal(t, "llm_policy.model_blocked", errObj["code"], "the NetBird code rides in the vendor code field")
	assert.Equal(t, "model is not in the policy allowlist", errObj["message"])
}

// TestRenderDeny_RateLimitStatusMapsToVendorRateLimit pins the mapping a
// client's backoff keys on.
func TestRenderDeny_RateLimitStatusMapsToVendorRateLimit(t *testing.T) {
	body, status := decodeDeny(t, &DenyReason{
		Code:    "llm_policy.token_cap_exceeded",
		Message: "LLM policy limit exceeded",
		Surface: "anthropic",
	}, http.StatusTooManyRequests)

	assert.Equal(t, http.StatusTooManyRequests, status, "429 must survive the status clamp")
	errObj := body["error"].(map[string]any)
	assert.Equal(t, "rate_limit_error", errObj["type"])
}

// TestRenderDeny_NoSurfaceKeepsLegacyShape guards non-LLM middlewares and
// denials raised before a surface is known.
func TestRenderDeny_NoSurfaceKeepsLegacyShape(t *testing.T) {
	body, _ := decodeDeny(t, &DenyReason{
		Code:    "llm_policy.model_not_routable",
		Message: "no provider configured for model x",
	}, http.StatusForbidden)

	assert.NotContains(t, body, "type", "no surface means no vendor mirror")
	assert.NotContains(t, body, "error", "no surface means no vendor mirror")
	assert.Equal(t, "llm_policy.model_not_routable", body["code"])
}
