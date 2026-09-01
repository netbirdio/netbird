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

// bedrockVendorNamespaces are the vendor segments a Bedrock model id is
// published under. They identify the geography in front of a cross-region
// inference profile without knowing the geography: in
// "eu.anthropic.claude-...", what makes "eu" a geography is that "anthropic"
// follows it.
//
// A vendor missing from here is not fatal — bedrockGeographies covers the
// same id from the other side — but it is one of the two ways an id can go
// unrecognised, and the list needs a new entry whenever AWS onboards a
// vendor. A live listing found "global.xai.grok-4.6" days after this was
// first written.
var bedrockVendorNamespaces = map[string]struct{}{
	"ai21":       {},
	"amazon":     {},
	"anthropic":  {},
	"cohere":     {},
	"deepseek":   {},
	"luma":       {},
	"meta":       {},
	"mistral":    {},
	"openai":     {},
	"qwen":       {},
	"stability":  {},
	"twelvelabs": {},
	"writer":     {},
	"xai":        {},
}

// bedrockGeographies are the geography segments AWS issues cross-region
// inference profiles under. They recognise a profile whose vendor we have
// never seen, which is the case bedrockVendorNamespaces alone gets wrong:
// "global.xai.grok-4.6" is a geography and a model whether or not "xai" is
// a name we know.
//
// Neither list is sufficient alone. A geography list on its own is what this
// file started with, and it aged badly — it held us, eu, apac and global, so
// every profile issued under jp, au, ca, sa or us-gov carried its prefix into
// the pricing key, matched no catalog entry, and reported the model unpriced.
// A vendor list on its own misses a new vendor under a known geography.
// Together, an id has to be new on both axes at once to go unrecognised.
var bedrockGeographies = map[string]struct{}{
	"apac":   {},
	"au":     {},
	"ca":     {},
	"eu":     {},
	"global": {},
	"jp":     {},
	"sa":     {},
	"us":     {},
	"us-gov": {},
}

// stripBedrockGeography removes the cross-region inference-profile geography
// from a Bedrock model id, leaving the "<vendor>.<model>" form the catalog and
// the pricing table key on.
//
// A leading segment counts as a geography when it is one we know, or when a
// known vendor follows it. Either alone is enough: the id has to be new on
// both axes before its geography survives.
//
// The segment has to be followed by two more, so "amazon.nova-pro" stays a
// vendor and a model rather than becoming a geography and a model — cutting
// its first segment would strip the vendor away. Over-stripping is the
// dangerous direction, because the result also decides which route may claim
// a model.
func stripBedrockGeography(modelID string) string {
	geo, rest, found := strings.Cut(modelID, ".")
	if !found || geo == "" {
		return modelID
	}
	vendor, _, found := strings.Cut(rest, ".")
	if !found {
		return modelID
	}
	if _, ok := bedrockGeographies[geo]; ok {
		return rest
	}
	if _, ok := bedrockVendorNamespaces[vendor]; ok {
		return rest
	}
	return modelID
}

// bedrockVersionSuffix matches the trailing "-vN[:N]" or "-YYYYMMDD-vN[:N]"
// version/throughput suffix of a Bedrock model id.
var bedrockVersionSuffix = regexp.MustCompile(`-(\d{8}-)?v\d+(:\d+)?$`)

// IsBedrockStyleModel reports whether a model id carries a positive Bedrock
// marker: an ARN wrapper, a known geography or vendor namespace as its first
// dotted segment, or a known vendor namespace as the segment a geography
// would precede. Callers without provider context gate the Bedrock
// normalization on it — the bare version-suffix strip must never fire on an
// id that is not recognizably Bedrock, or a plain provider's "-vN"-suffixed
// model would canonicalize into a different model's id.
func IsBedrockStyleModel(modelID string) bool {
	if strings.HasPrefix(modelID, "arn:") {
		return true
	}
	first, rest, found := strings.Cut(modelID, ".")
	if !found || first == "" || rest == "" {
		return false
	}
	if _, ok := bedrockGeographies[first]; ok {
		return true
	}
	if _, ok := bedrockVendorNamespaces[first]; ok {
		return true
	}
	second, _, found := strings.Cut(rest, ".")
	if !found {
		return false
	}
	_, ok := bedrockVendorNamespaces[second]
	return ok
}

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
	m = stripBedrockGeography(m)
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
