// Package llm_response_parser implements the SlotOnResponse middleware
// that decodes OpenAI- and Anthropic-shaped LLM responses (buffered or
// streaming) and emits token usage and completion metadata. Provider
// and model are read from the request-side metadata bag emitted by
// llm_request_parser; without that context the middleware is a no-op.
package llm_response_parser

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/llm"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_guardrail"
)

// ID is the registry identifier for this middleware.
const ID = "llm_response_parser"

const version = "1.0.0"

// maxCompletionBytes is the rune-safe cap applied to the extracted
// completion text before emitting it as metadata.
const maxCompletionBytes = 3500

// maxDecodedBytes bounds the inflated size of a compressed response body
// so a small gzip/deflate payload can't expand into a memory blow-up. The
// captured input is already capped (per-direction body cap), so this only
// bounds the decompression ratio; the parser is best-effort and tolerates a
// truncated decode.
const maxDecodedBytes = 16 << 20

var (
	acceptedContentTypes = []string{"application/json", "text/event-stream"}
	metadataKeys         = []string{
		middleware.KeyLLMInputTokens,
		middleware.KeyLLMOutputTokens,
		middleware.KeyLLMTotalTokens,
		middleware.KeyLLMCachedInputTokens,
		middleware.KeyLLMCacheCreationTokens,
		middleware.KeyLLMResponseCompletion,
	}
)

// config is the wire-side configuration for this middleware. RedactPii, when
// true, runs PII redaction on the extracted completion text BEFORE it is
// emitted as llm.response_completion — keeping the access-log row free of
// emails / SSNs / phone numbers the model itself generated. CaptureCompletion
// gates emission of the completion key entirely: a nil pointer preserves
// legacy emission (so callers without the toggle aren't broken), an explicit
// false suppresses the key so the access-log row carries token / cost facts
// only. Both are sourced by the synthesiser from the account's redact_pii
// and enable_prompt_collection toggles respectively.
type config struct {
	RedactPii         bool  `json:"redact_pii,omitempty"`
	CaptureCompletion *bool `json:"capture_completion,omitempty"`
}

// Middleware implements middleware.Middleware.
type Middleware struct {
	parsers           []llm.Parser
	redactPii         bool
	captureCompletion bool
}

// New constructs a configured Middleware instance.
func New(cfg config) *Middleware {
	capture := true
	if cfg.CaptureCompletion != nil {
		capture = *cfg.CaptureCompletion
	}
	return &Middleware{parsers: llm.Parsers(), redactPii: cfg.RedactPii, captureCompletion: capture}
}

// ID returns the registry identifier.
func (m *Middleware) ID() string { return ID }

// Version returns the implementation version.
func (m *Middleware) Version() string { return version }

// Slot reports that the middleware runs after the upstream call.
func (m *Middleware) Slot() middleware.Slot { return middleware.SlotOnResponse }

// AcceptedContentTypes lists the response content types the middleware
// inspects.
func (m *Middleware) AcceptedContentTypes() []string {
	return append([]string(nil), acceptedContentTypes...)
}

// MetadataKeys returns the closed allowlist of keys this middleware
// may emit.
func (m *Middleware) MetadataKeys() []string {
	return append([]string(nil), metadataKeys...)
}

// MutationsSupported reports that this middleware never mutates the
// response.
func (m *Middleware) MutationsSupported() bool { return false }

// Close releases any resources held by the middleware. The parser-set
// is stateless so this is a no-op.
func (m *Middleware) Close() error { return nil }

// Invoke decodes the response body and emits token-usage and completion
// metadata. The decision is always DecisionAllow; parse errors degrade
// silently to omitted metadata rather than chain failures.
func (m *Middleware) Invoke(_ context.Context, in *middleware.Input) (*middleware.Output, error) {
	out := &middleware.Output{Decision: middleware.DecisionAllow}
	if in == nil {
		return out, nil
	}

	provider := lookupKV(in.Metadata, middleware.KeyLLMProvider)
	if provider == "" {
		return out, nil
	}

	parser := m.parserByName(provider)
	if parser == nil {
		return out, nil
	}

	// Upstreams compress the response when the client negotiated it
	// (Claude Code sends Accept-Encoding: gzip). The transport leaves it
	// compressed because the request carried an explicit Accept-Encoding,
	// so the captured copy is gzip/deflate bytes — decompress it before
	// parsing or token usage is silently lost. The forwarded client
	// stream is untouched; this only affects our parse copy.
	body := decodeResponseBody(in.RespBody, headerLookup(in.RespHeaders, "Content-Encoding"))

	contentType := headerLookup(in.RespHeaders, "Content-Type")
	logRawResponse(provider, contentType, in.Status, body)
	switch {
	case isEventStream(contentType), isAWSEventStream(contentType):
		out.Metadata = m.invokeStreaming(parser, body)
	case isJSON(contentType):
		out.Metadata = m.invokeBuffered(parser, in, contentType, body)
	}

	return out, nil
}

// debugLogRawBytes caps how much of a raw upstream response body the debug
// log carries. Enough to inspect a full usage block and the surrounding
// envelope without flooding the log with multi-megabyte completions.
const debugLogRawBytes = 4096

// debugLogger returns the proxy logger when debug logging is enabled, nil
// otherwise. All cost-audit logging in this middleware is debug-only so the
// hot path stays quiet at production log levels.
func debugLogger() *log.Logger {
	logger := builtin.Context().Logger
	if logger == nil || !logger.IsLevelEnabled(log.DebugLevel) {
		return nil
	}
	return logger
}

// logRawResponse debug-logs the (decompressed) upstream response body so an
// operator can compare the provider's own usage block against the token
// counts and cost the proxy derives from it. Bodies are truncated and
// %q-quoted, so binary AWS event-stream framing stays log-safe.
func logRawResponse(provider, contentType string, status int, body []byte) {
	logger := debugLogger()
	if logger == nil {
		return
	}
	shown := body
	truncated := false
	if len(shown) > debugLogRawBytes {
		shown = shown[:debugLogRawBytes]
		truncated = true
	}
	logger.WithFields(log.Fields{
		"middleware":   ID,
		"provider":     provider,
		"status":       status,
		"content_type": contentType,
		"body_bytes":   len(body),
		"truncated":    truncated,
	}).Debugf("llm raw response body: %q", shown)
}

// logParsedUsage debug-logs the token counts extracted from the upstream
// response — the exact values the cost meter will price.
func logParsedUsage(provider, mode string, usage llm.Usage) {
	logger := debugLogger()
	if logger == nil {
		return
	}
	logger.WithFields(log.Fields{
		"middleware": ID,
		"provider":   provider,
		"mode":       mode,
	}).Debugf("llm response tokens: input=%d output=%d cache_read=%d cache_creation=%d total=%d",
		usage.InputTokens, usage.OutputTokens, usage.CachedInputTokens, usage.CacheCreationTokens, usage.TotalTokens)
}

// invokeBuffered decodes a non-streaming JSON response body. Status
// codes >= 400 short-circuit because providers don't include usage on
// error responses.
func (m *Middleware) invokeBuffered(parser llm.Parser, in *middleware.Input, contentType string, body []byte) []middleware.KV {
	if in.Status >= 400 {
		return nil
	}

	var md []middleware.KV

	usage, err := parser.ParseResponse(in.Status, contentType, body)
	if err == nil {
		md = appendUsage(md, usage)
		logParsedUsage(parser.ProviderName(), "buffered", usage)
	} else if logger := debugLogger(); logger != nil {
		logger.WithFields(log.Fields{"middleware": ID, "provider": parser.ProviderName()}).
			Debugf("llm response usage not extracted: %v", err)
	}

	if completion := truncateCompletion(parser.ExtractCompletion(in.Status, contentType, body)); completion != "" && m.captureCompletion {
		if m.redactPii {
			completion = llm_guardrail.RedactPII(completion)
		}
		md = append(md, middleware.KV{Key: middleware.KeyLLMResponseCompletion, Value: completion})
	}

	return md
}

// invokeStreaming walks the buffered SSE prefix and accumulates token
// deltas plus completion text. Truncated bodies are processed
// best-effort; partial usage is preferred over no metadata.
func (m *Middleware) invokeStreaming(parser llm.Parser, body []byte) []middleware.KV {
	if len(body) == 0 {
		return nil
	}

	usage, completion := accumulateStream(parser.ProviderName(), body)
	logParsedUsage(parser.ProviderName(), "streaming", usage)

	var md []middleware.KV
	if usage.InputTokens > 0 || usage.OutputTokens > 0 || usage.TotalTokens > 0 {
		md = appendUsage(md, usage)
	}
	if c := truncateCompletion(completion); c != "" && m.captureCompletion {
		if m.redactPii {
			c = llm_guardrail.RedactPII(c)
		}
		md = append(md, middleware.KV{Key: middleware.KeyLLMResponseCompletion, Value: c})
	}
	return md
}

// parserByName returns the parser matching the provider label emitted
// by llm_request_parser, or nil when none claims it.
func (m *Middleware) parserByName(name string) llm.Parser {
	for _, p := range m.parsers {
		if p.ProviderName() == name {
			return p
		}
	}
	return nil
}

// appendUsage emits the three baseline token-count metadata keys plus
// optional cached / cache-creation bucket counts when nonzero. Total
// is computed when the provider omitted one but reported per-direction
// counts; cache buckets are excluded from the legacy total because
// llm.input_tokens already absorbs the OpenAI cached subset and the
// sum-of-everything is a separate downstream concern.
func appendUsage(md []middleware.KV, usage llm.Usage) []middleware.KV {
	total := usage.TotalTokens
	if total == 0 && (usage.InputTokens > 0 || usage.OutputTokens > 0) {
		total = usage.InputTokens + usage.OutputTokens
	}
	md = append(md,
		middleware.KV{Key: middleware.KeyLLMInputTokens, Value: strconv.FormatInt(usage.InputTokens, 10)},
		middleware.KV{Key: middleware.KeyLLMOutputTokens, Value: strconv.FormatInt(usage.OutputTokens, 10)},
		middleware.KV{Key: middleware.KeyLLMTotalTokens, Value: strconv.FormatInt(total, 10)},
	)
	if usage.CachedInputTokens > 0 {
		md = append(md, middleware.KV{
			Key:   middleware.KeyLLMCachedInputTokens,
			Value: strconv.FormatInt(usage.CachedInputTokens, 10),
		})
	}
	if usage.CacheCreationTokens > 0 {
		md = append(md, middleware.KV{
			Key:   middleware.KeyLLMCacheCreationTokens,
			Value: strconv.FormatInt(usage.CacheCreationTokens, 10),
		})
	}
	return md
}

// truncateCompletion clamps an extracted completion to maxCompletionBytes.
// The cut is rune-safe so we never split a multi-byte UTF-8 sequence.
func truncateCompletion(s string) string {
	if len(s) <= maxCompletionBytes {
		return s
	}
	cut := maxCompletionBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func lookupKV(kvs []middleware.KV, key string) string {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value
		}
	}
	return ""
}

func headerLookup(h []middleware.KV, name string) string {
	lower := strings.ToLower(name)
	for _, kv := range h {
		if strings.ToLower(kv.Key) == lower {
			return kv.Value
		}
	}
	return ""
}

func isEventStream(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

// isAWSEventStream reports whether contentType is the AWS binary event-stream
// framing used by Bedrock's streaming endpoints.
func isAWSEventStream(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "application/vnd.amazon.eventstream")
}

func isJSON(contentType string) bool {
	lower := strings.ToLower(contentType)
	return strings.Contains(lower, "application/json") || strings.Contains(lower, "+json")
}

// decodeResponseBody returns body decompressed per its Content-Encoding,
// or the original bytes when the encoding is identity, unrecognised
// (e.g. br — no stdlib decoder), or the body isn't actually compressed.
// Decoding is best-effort: a truncated stream (capture hit the byte cap)
// yields the decompressed prefix rather than an error, which is enough to
// recover the leading message_start usage on Anthropic SSE.
func decodeResponseBody(body []byte, contentEncoding string) []byte {
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	// Content-Encoding may list multiple codings; the last applied is
	// the outermost on the wire.
	if idx := strings.LastIndex(enc, ","); idx >= 0 {
		enc = strings.TrimSpace(enc[idx+1:])
	}
	switch enc {
	case "", "identity":
		return body
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body
		}
		defer zr.Close()
		if out := readCapped(zr); len(out) > 0 {
			return out
		}
		return body
	case "deflate":
		// "deflate" on the wire is usually zlib-wrapped; fall back to raw
		// flate when there's no zlib header.
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			defer zr.Close()
			if out := readCapped(zr); len(out) > 0 {
				return out
			}
			return body
		}
		fr := flate.NewReader(bytes.NewReader(body))
		defer fr.Close()
		if out := readCapped(fr); len(out) > 0 {
			return out
		}
		return body
	default:
		return body
	}
}

// readCapped reads at most maxDecodedBytes from r, discarding any excess.
// Best-effort: a read error returns whatever was decoded so far, which is
// enough for the parser to recover leading usage events.
func readCapped(r io.Reader) []byte {
	out, _ := io.ReadAll(io.LimitReader(r, maxDecodedBytes))
	return out
}
