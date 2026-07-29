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
// source of truth shared by the request parser (which normalizes the request
// model from the URL path) and the router (which normalizes the operator's
// registered Bedrock model ids so both sides compare equal).
func NormalizeBedrockModel(modelID string) string {
	m := modelID
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
