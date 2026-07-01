// Package llm_request_parser implements the SlotOnRequest middleware
// that detects the LLM provider from the request URL, parses the JSON
// request body for model and streaming flags, and extracts the user
// prompt text. Emitted metadata feeds downstream middlewares (guardrail,
// cost meter) and the access-log terminal sink.
package llm_request_parser

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/netbirdio/netbird/proxy/internal/llm"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_guardrail"
)

// ID is the registry key for this middleware.
const ID = "llm_request_parser"

// Version is reported via Middleware.Version().
const Version = "1.0.0"

// maxPromptBytes caps llm.request_prompt_raw at a size that fits within
// MaxMetadataValueBytes with headroom. Truncation is rune-safe.
const maxPromptBytes = 3500

// middlewareImpl is the concrete implementation. providerID, when set,
// names the parser to use directly (bypasses URL sniffing). It is empty
// for non-agent-network targets, which fall back to DetectParser on the
// request path.
type middlewareImpl struct {
	providerID    string
	redactPii     bool
	capturePrompt bool
}

// ID returns the registry identifier.
func (middlewareImpl) ID() string { return ID }

// Version returns the implementation version.
func (middlewareImpl) Version() string { return Version }

// Slot reports the request slot.
func (middlewareImpl) Slot() middleware.Slot { return middleware.SlotOnRequest }

// AcceptedContentTypes restricts body inspection to JSON.
func (middlewareImpl) AcceptedContentTypes() []string {
	return []string{"application/json"}
}

// MetadataKeys lists the closed allowlist of keys this middleware emits.
func (middlewareImpl) MetadataKeys() []string {
	return []string{
		middleware.KeyLLMProvider,
		middleware.KeyLLMModel,
		middleware.KeyLLMStream,
		middleware.KeyLLMRequestPromptRaw,
		middleware.KeyLLMCaptureTruncated,
		middleware.KeyLLMSessionID,
	}
}

// MutationsSupported reports that this middleware never mutates.
func (middlewareImpl) MutationsSupported() bool { return false }

// Close is a no-op; the middleware is stateless.
func (middlewareImpl) Close() error { return nil }

// Invoke detects the LLM provider, parses request facts, and emits
// metadata. Always returns DecisionAllow; never errors. Provider
// selection prefers the configured providerID (synthesiser-stamped on
// agent-network targets) so requests routed to a custom upstream URL
// still resolve. Falls back to URL sniffing when no providerID is set.
func (m middlewareImpl) Invoke(_ context.Context, in *middleware.Input) (*middleware.Output, error) {
	out := &middleware.Output{Decision: middleware.DecisionAllow}
	if in == nil {
		return out, nil
	}

	// Google Vertex AI carries the model + publisher (vendor) in the URL path,
	// not the body, so it needs a dedicated extraction path.
	if vx, okv := parseVertexPath(extractPath(in.URL)); okv {
		return m.invokeVertex(in, vx), nil
	}

	// AWS Bedrock likewise carries the model in the URL path (/model/{id}/{action}).
	if br, okb := parseBedrockPath(extractPath(in.URL)); okb {
		return m.invokeBedrock(in, br), nil
	}

	parser, ok := llm.ParserByName(m.providerID)
	if !ok {
		parser, ok = llm.DetectParser(extractPath(in.URL))
	}
	if !ok {
		return out, nil
	}

	md := []middleware.KV{
		{Key: middleware.KeyLLMProvider, Value: parser.ProviderName()},
	}

	// Session id is an opaque grouping identifier, not prompt content, so
	// it's emitted regardless of the prompt-collection toggle — session
	// grouping must work even when prompt capture is off. Prefer a header
	// (Codex sends the session as an HTTP header, and headers survive an
	// oversized request whose body capture was bypassed) and resolve it
	// before ParseRequest so a malformed body still keeps the header id.
	sessionID := sessionIDFromHeaders(in.Headers)
	if sessionID == "" {
		sessionID = parser.ExtractSessionID(in.Body)
	}
	appendSessionID := func(md []middleware.KV) []middleware.KV {
		if sessionID != "" {
			return append(md, middleware.KV{Key: middleware.KeyLLMSessionID, Value: sessionID})
		}
		return md
	}

	facts, err := parser.ParseRequest(in.Body)
	if err != nil {
		if logger := builtin.Context().Logger; logger != nil {
			logger.Debugf("llm_request_parser: parse request body: %v", err)
		}
		md = appendSessionID(md)
		md = appendCaptureTruncated(md, false, in.BodyTruncated)
		out.Metadata = md
		return out, nil
	}

	if facts.Model != "" {
		md = append(md, middleware.KV{Key: middleware.KeyLLMModel, Value: facts.Model})
	}
	md = append(md, middleware.KV{Key: middleware.KeyLLMStream, Value: strconv.FormatBool(facts.Stream)})
	md = appendSessionID(md)

	prompt, promptTruncated := truncatePrompt(parser.ExtractPrompt(in.Body))
	if prompt != "" && m.capturePrompt {
		if m.redactPii {
			// Apply redaction BEFORE the value lands in the metadata bag, so
			// the access-log row never carries raw emails / SSNs / phones.
			// The downstream llm_guardrail middleware reads this key to
			// produce llm.request_prompt; RedactPII is idempotent so its
			// second pass is a no-op. Redaction can grow the text, so
			// re-truncate to keep the value within the metadata cap.
			prompt = llm_guardrail.RedactPII(prompt)
			var redactedTruncated bool
			prompt, redactedTruncated = truncatePrompt(prompt)
			promptTruncated = promptTruncated || redactedTruncated
		}
		md = append(md, middleware.KV{Key: middleware.KeyLLMRequestPromptRaw, Value: prompt})
	}

	md = appendCaptureTruncated(md, promptTruncated, in.BodyTruncated)
	out.Metadata = md
	return out, nil
}

// sessionIDHeaders are request header names that may carry a client
// session identifier, checked in order, case-insensitively. Matching is
// against Go's canonical header form, so use the hyphenated names the
// clients actually send: "x-claude-code-session-id" (Claude Code),
// "session-id" (OpenAI Codex — confirmed on the wire as "Session-Id"),
// and "x-session-id" as a generic convention.
var sessionIDHeaders = []string{"x-claude-code-session-id", "session-id", "x-session-id"}

// sessionIDFromHeaders returns the first non-empty value among the known
// session header names, or "" when none is present. Headers arrive in
// canonical form, so the match is case-insensitive.
func sessionIDFromHeaders(headers []middleware.KV) string {
	for _, want := range sessionIDHeaders {
		for _, kv := range headers {
			if strings.EqualFold(kv.Key, want) && kv.Value != "" {
				return kv.Value
			}
		}
	}
	return ""
}

// appendCaptureTruncated stamps the capture_truncated marker reflecting
// either prompt-side truncation or upstream body truncation.
func appendCaptureTruncated(md []middleware.KV, promptTruncated, bodyTruncated bool) []middleware.KV {
	value := "false"
	if promptTruncated || bodyTruncated {
		value = "true"
	}
	return append(md, middleware.KV{Key: middleware.KeyLLMCaptureTruncated, Value: value})
}

// truncatePrompt clamps a prompt string to maxPromptBytes on a UTF-8
// rune boundary. Returns the clamped string and whether truncation
// occurred.
func truncatePrompt(s string) (string, bool) {
	if len(s) <= maxPromptBytes {
		return s, false
	}
	cut := maxPromptBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

// extractPath returns the path component of a URL that may be absolute
// or already a path. Parse errors fall back to the raw input.
func extractPath(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return raw
	}
	return u.Path
}

// vertexRequest is the model + vendor extracted from a Vertex AI publisher
// path (the model is in the URL, not the body).
type vertexRequest struct {
	publisher string
	model     string
	stream    bool
}

// parseVertexPath extracts the publisher, model, and streaming flag from a
// Vertex publisher endpoint:
//
//	/v1/projects/{project}/locations/{region}/publishers/{publisher}/models/{model}:{action}
//
// The model's "@version" suffix is stripped so it matches catalog/pricing.
func parseVertexPath(reqPath string) (vertexRequest, bool) {
	const pubSep, modSep = "/publishers/", "/models/"
	if !strings.HasPrefix(reqPath, "/v1/projects/") {
		return vertexRequest{}, false
	}
	pubIdx := strings.Index(reqPath, pubSep)
	modIdx := strings.Index(reqPath, modSep)
	if pubIdx < 0 || modIdx <= pubIdx {
		return vertexRequest{}, false
	}
	publisher := reqPath[pubIdx+len(pubSep) : modIdx]
	rest := reqPath[modIdx+len(modSep):] // {model}:{action}
	if publisher == "" || rest == "" {
		return vertexRequest{}, false
	}
	model, action := rest, ""
	if c := strings.LastIndex(rest, ":"); c >= 0 {
		model, action = rest[:c], rest[c+1:]
	}
	if at := strings.Index(model, "@"); at >= 0 {
		model = model[:at]
	}
	if model == "" {
		return vertexRequest{}, false
	}
	return vertexRequest{publisher: publisher, model: model, stream: strings.HasPrefix(action, "stream")}, true
}

// vertexPublisherVendor maps a Vertex publisher to the parser surface its
// requests/responses speak. Empty for publishers without a parser yet
// (e.g. google/gemini) — the request still routes, but isn't metered.
func vertexPublisherVendor(publisher string) string {
	switch strings.ToLower(publisher) {
	case "anthropic":
		return "anthropic"
	case "openai":
		return "openai"
	default:
		return ""
	}
}

// invokeVertex emits the model/vendor/session/prompt for a Vertex publisher
// request, using the publisher's parser to read the (vendor-native) body.
func (m middlewareImpl) invokeVertex(in *middleware.Input, vx vertexRequest) *middleware.Output {
	out := &middleware.Output{Decision: middleware.DecisionAllow}
	vendor := vertexPublisherVendor(vx.publisher)

	md := []middleware.KV{}
	if vendor != "" {
		md = append(md, middleware.KV{Key: middleware.KeyLLMProvider, Value: vendor})
	}
	md = append(md, middleware.KV{Key: middleware.KeyLLMModel, Value: vx.model})
	md = append(md, middleware.KV{Key: middleware.KeyLLMStream, Value: strconv.FormatBool(vx.stream)})

	var parser llm.Parser
	if vendor != "" {
		parser, _ = llm.ParserByName(vendor)
	}

	sessionID := sessionIDFromHeaders(in.Headers)
	if sessionID == "" && parser != nil {
		sessionID = parser.ExtractSessionID(in.Body)
	}
	if sessionID != "" {
		md = append(md, middleware.KV{Key: middleware.KeyLLMSessionID, Value: sessionID})
	}

	promptTruncated := false
	if parser != nil && m.capturePrompt {
		var prompt string
		prompt, promptTruncated = truncatePrompt(parser.ExtractPrompt(in.Body))
		if prompt != "" {
			if m.redactPii {
				prompt = llm_guardrail.RedactPII(prompt)
				var rt bool
				prompt, rt = truncatePrompt(prompt)
				promptTruncated = promptTruncated || rt
			}
			md = append(md, middleware.KV{Key: middleware.KeyLLMRequestPromptRaw, Value: prompt})
		}
	}
	md = appendCaptureTruncated(md, promptTruncated, in.BodyTruncated)
	out.Metadata = md
	return out
}

// bedrockRequest is the model + streaming flag extracted from an AWS Bedrock
// model path. The InvokeModel vs Converse distinction is recovered downstream
// from the response body shape, so only the streaming flag is carried here.
type bedrockRequest struct {
	model  string
	stream bool
}

// bedrockNamespacePrefix is an optional gateway-namespace prefix some clients
// put before the native Bedrock path to disambiguate it from other providers
// that also use "/model/...".
const bedrockNamespacePrefix = "/bedrock"

// trimBedrockNamespace removes an optional "/bedrock" namespace prefix, leaving
// the native Bedrock path ("/model/...").
func trimBedrockNamespace(reqPath string) string {
	if strings.HasPrefix(reqPath, bedrockNamespacePrefix+"/") {
		return strings.TrimPrefix(reqPath, bedrockNamespacePrefix)
	}
	return reqPath
}

// bedrockRegionPrefixes are the cross-region inference-profile prefixes that
// front a Bedrock model id (e.g. "eu.anthropic.claude-...").
var bedrockRegionPrefixes = []string{"us.", "eu.", "apac.", "global."}

// bedrockVersionSuffix matches the trailing "-vN[:N]" or "-YYYYMMDD-vN[:N]"
// version/throughput suffix of a Bedrock model id.
var bedrockVersionSuffix = regexp.MustCompile(`-(\d{8}-)?v\d+(:\d+)?$`)

// parseBedrockPath extracts the model and streaming/converse flags from an AWS
// Bedrock runtime model endpoint:
//
//	/model/{modelId}/{action}
//
// action ∈ {invoke, invoke-with-response-stream, converse, converse-stream}.
// The modelId may be URL-encoded and may carry a cross-region inference-profile
// prefix and a version suffix; normalizeBedrockModel strips both so the model
// matches catalog pricing.
func parseBedrockPath(reqPath string) (bedrockRequest, bool) {
	reqPath = trimBedrockNamespace(reqPath)
	const prefix = "/model/"
	if !strings.HasPrefix(reqPath, prefix) {
		return bedrockRequest{}, false
	}
	rest := reqPath[len(prefix):]
	slash := strings.LastIndex(rest, "/")
	if slash <= 0 || slash == len(rest)-1 {
		return bedrockRequest{}, false
	}
	rawModel, action := rest[:slash], rest[slash+1:]
	if decoded, err := url.PathUnescape(rawModel); err == nil {
		rawModel = decoded
	}
	model := normalizeBedrockModel(rawModel)
	if model == "" {
		return bedrockRequest{}, false
	}
	switch action {
	case "invoke", "converse":
		return bedrockRequest{model: model}, true
	case "invoke-with-response-stream", "converse-stream":
		return bedrockRequest{model: model, stream: true}, true
	default:
		return bedrockRequest{}, false
	}
}

// normalizeBedrockModel strips an ARN wrapper, a cross-region inference-profile
// prefix, and the version/throughput suffix from a Bedrock model id so it
// matches the catalog/pricing key, e.g.
// "eu.anthropic.claude-sonnet-4-5-20250929-v1:0" -> "anthropic.claude-sonnet-4-5"
// and "arn:aws:bedrock:eu-central-1:123:inference-profile/eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
// -> "anthropic.claude-sonnet-4-5".
func normalizeBedrockModel(modelID string) string {
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

// invokeBedrock emits the model/provider/session/prompt for an AWS Bedrock
// request. Bedrock is metered under the dedicated "bedrock" parser, which reads
// both the InvokeModel and Converse response shapes.
func (m middlewareImpl) invokeBedrock(in *middleware.Input, br bedrockRequest) *middleware.Output {
	out := &middleware.Output{Decision: middleware.DecisionAllow}
	md := []middleware.KV{
		{Key: middleware.KeyLLMProvider, Value: llm.ProviderNameBedrock},
		{Key: middleware.KeyLLMModel, Value: br.model},
		{Key: middleware.KeyLLMStream, Value: strconv.FormatBool(br.stream)},
	}

	parser, _ := llm.ParserByName(llm.ProviderNameBedrock)
	sessionID := sessionIDFromHeaders(in.Headers)
	if sessionID == "" && parser != nil {
		sessionID = parser.ExtractSessionID(in.Body)
	}
	if sessionID != "" {
		md = append(md, middleware.KV{Key: middleware.KeyLLMSessionID, Value: sessionID})
	}

	promptTruncated := false
	if parser != nil && m.capturePrompt {
		var prompt string
		prompt, promptTruncated = truncatePrompt(parser.ExtractPrompt(in.Body))
		if prompt != "" {
			if m.redactPii {
				prompt = llm_guardrail.RedactPII(prompt)
				var rt bool
				prompt, rt = truncatePrompt(prompt)
				promptTruncated = promptTruncated || rt
			}
			md = append(md, middleware.KV{Key: middleware.KeyLLMRequestPromptRaw, Value: prompt})
		}
	}
	md = appendCaptureTruncated(md, promptTruncated, in.BodyTruncated)
	out.Metadata = md
	return out
}
