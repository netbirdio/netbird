// Package llm holds LLM model-identifier helpers shared by the proxy and
// the management server. The proxy normalizes model ids parsed off inbound
// requests; management normalizes the operator's registered model ids at
// synthesis time so both sides of the pricing / routing contract compare
// equal.
package llm

import (
	"regexp"
	"strings"
)

// bedrockRegionPrefixes are the cross-region inference-profile prefixes that
// front a Bedrock model id (e.g. "eu.anthropic.claude-...").
var bedrockRegionPrefixes = []string{"us.", "eu.", "apac.", "global."}

// bedrockVersionSuffix matches the trailing "-vN[:N]" or "-YYYYMMDD-vN[:N]"
// version/throughput suffix of a Bedrock model id.
var bedrockVersionSuffix = regexp.MustCompile(`-(\d{8}-)?v\d+(:\d+)?$`)

// NormalizeBedrockModel strips an ARN wrapper, a cross-region inference-profile
// prefix, and the version/throughput suffix from a Bedrock model id so it
// matches the catalog/pricing key, e.g.
// "eu.anthropic.claude-sonnet-4-5-20250929-v1:0" -> "anthropic.claude-sonnet-4-5"
// and the inference-profile ARN's last segment likewise. It is the single
// source of truth shared by the proxy's request parser (which normalizes the
// request model from the URL path), the proxy's router (which normalizes the
// operator's registered Bedrock model ids so both sides compare equal), and
// the management synthesizer (which keys per-provider pricing entries by the
// normalized id the parser will emit at billing time).
func NormalizeBedrockModel(modelID string) string {
	m := modelID
	// A full ARN (inference-profile / provisioned-throughput / foundation-model)
	// carries the model id in its last path segment.
	if strings.HasPrefix(m, "arn:") {
		if i := strings.LastIndex(m, "/"); i >= 0 {
			m = m[i+1:]
		}
	}
	for _, p := range bedrockRegionPrefixes {
		if strings.HasPrefix(m, p) {
			m = m[len(p):]
			break
		}
	}
	return bedrockVersionSuffix.ReplaceAllString(m, "")
}

// anthropicDatedModel matches a Claude model id carrying the trailing
// "-YYYYMMDD" release-date suffix Anthropic appends to a pinned release,
// capturing the id without it. The "claude" anchor is load-bearing: pricing
// looks every model up through this helper regardless of surface, and an
// operator may register a custom id with any shape at all, so an unanchored
// "-\d{8}$" would let "internal-llm-20250101" silently inherit the rate
// registered for "internal-llm". The anchor also covers the vendor-prefixed
// forms ("anthropic.claude-...", "us.anthropic.claude-...").
var anthropicDatedModel = regexp.MustCompile(`(?i)^(.*claude.*)-\d{8}$`)

// NormalizeAnthropicModel strips the trailing release-date suffix from a
// Claude model id, e.g. "claude-sonnet-4-5-20250929" -> "claude-sonnet-4-5",
// so a dated id a client pins matches the undated one the operator
// registered. Ids that are not Claude-family are returned untouched.
// Callers try the verbatim id first and fall back to this, so two dated
// releases of the same family stay distinct wherever both are registered
// explicitly.
func NormalizeAnthropicModel(modelID string) string {
	return anthropicDatedModel.ReplaceAllString(modelID, "$1")
}

// NormalizeVertexModel strips the "@version" suffix from a Vertex AI model id
// (e.g. "claude-sonnet-4-5@20250929" -> "claude-sonnet-4-5") so it matches
// the catalog/pricing key. Vertex publisher models are priced under their
// vendor surface with the bare, unversioned id.
func NormalizeVertexModel(modelID string) string {
	if at := strings.Index(modelID, "@"); at >= 0 {
		return modelID[:at]
	}
	return modelID
}
