package llm_response_parser

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netbirdio/netbird/proxy/internal/llm"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// newMeteredMiddleware returns a Middleware whose token metrics are
// backed by a fresh ManualReader, bypassing the process-wide instance.
func newMeteredMiddleware(t *testing.T) (*Middleware, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m := newTestMiddleware(t)
	m.metrics = newTokenMetrics(provider.Meter("test"))
	return m, reader
}

// sums collects the int64 counter named name into label -> value, keeping
// only data points that carry every attribute in want.
func sums(t *testing.T, reader *sdkmetric.ManualReader, name, label string, want ...attribute.KeyValue) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm), "collect must succeed")

	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			if md.Name != name {
				continue
			}
			sum, ok := md.Data.(metricdata.Sum[int64])
			require.True(t, ok, "%s must be an int64 sum", name)
			for _, dp := range sum.DataPoints {
				match := true
				for _, w := range want {
					if got, ok := dp.Attributes.Value(w.Key); !ok || got != w.Value {
						match = false
						break
					}
				}
				if !match {
					continue
				}
				v, _ := dp.Attributes.Value(attribute.Key(label))
				out[v.AsString()] += dp.Value
			}
		}
	}
	return out
}

// tokenSums is proxy.llm.tokens_total by kind.
func tokenSums(t *testing.T, reader *sdkmetric.ManualReader, want ...attribute.KeyValue) map[string]int64 {
	t.Helper()
	return sums(t, reader, "proxy.llm.tokens_total", "kind", want...)
}

// responseSums is proxy.llm.responses_total by result.
func responseSums(t *testing.T, reader *sdkmetric.ManualReader, want ...attribute.KeyValue) map[string]int64 {
	t.Helper()
	return sums(t, reader, "proxy.llm.responses_total", "result", want...)
}

// anthropicInput is a response from Anthropic for the given body and
// content type.
func anthropicInput(status int, contentType string, body []byte) *middleware.Input {
	return &middleware.Input{
		Slot:        middleware.SlotOnResponse,
		AccountID:   "acct-1",
		Status:      status,
		RespHeaders: []middleware.KV{{Key: "Content-Type", Value: contentType}},
		RespBody:    body,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMProvider, Value: "anthropic"},
			{Key: middleware.KeyLLMModel, Value: "claude-sonnet-4-5"},
		},
	}
}

func TestTokenMetrics_AnthropicBuffered(t *testing.T) {
	m, reader := newMeteredMiddleware(t)

	_, err := m.Invoke(context.Background(), anthropicInput(200, "application/json", loadFixture(t, "anthropic_messages.json")))
	require.NoError(t, err, "Invoke must not error")

	got := tokenSums(t, reader,
		attribute.String("account_id", "acct-1"),
		attribute.String("provider", "anthropic"),
		attribute.String("model", "claude-sonnet-4-5"),
	)
	assert.Equal(t, map[string]int64{"input": 123, "output": 45}, got,
		"zero cache buckets must not create series; input/output must match fixture")
	assert.Equal(t, map[string]int64{resultParsed: 1}, responseSums(t, reader,
		attribute.String("account_id", "acct-1"),
		attribute.String("provider", "anthropic"),
		attribute.String("model", "claude-sonnet-4-5"),
		attribute.String("mode", modeBuffered),
	), "a parsed JSON response must count once as buffered/parsed, with its account, provider and model")
}

func TestTokenMetrics_AnthropicStreaming(t *testing.T) {
	m, reader := newMeteredMiddleware(t)

	_, err := m.Invoke(context.Background(), anthropicInput(200, "text/event-stream", loadFixture(t, "anthropic_stream.txt")))
	require.NoError(t, err, "Invoke must not error")

	assert.Equal(t, map[string]int64{"input": 123, "output": 45}, tokenSums(t, reader),
		"input from message_start and output from the final message_delta must both count")
	assert.Equal(t, map[string]int64{resultParsed: 1}, responseSums(t, reader,
		attribute.String("account_id", "acct-1"),
		attribute.String("provider", "anthropic"),
		attribute.String("model", "claude-sonnet-4-5"),
		attribute.String("mode", modeStreaming),
	), "a complete stream must count once as streaming/parsed, with its account, provider and model")
}

func TestTokenMetrics_TruncatedStreamCountsPrefix(t *testing.T) {
	m, reader := newMeteredMiddleware(t)

	// Only the message_start event survives the capture cap: the input
	// is known, the final output count is not.
	body := loadFixture(t, "anthropic_stream.txt")
	end := bytes.Index(body, []byte("\n\n"))
	require.Positive(t, end, "fixture must hold more than one event")
	in := anthropicInput(200, "text/event-stream", body[:end+2])
	in.RespBodyTruncated = true

	_, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "Invoke must not error")

	got := tokenSums(t, reader)
	assert.Equal(t, int64(123), got["input"], "the prefix's input usage must still count")
	assert.Less(t, got["output"], int64(45), "output past the cut must be missing")
	assert.Equal(t, map[string]int64{resultTruncated: 1}, responseSums(t, reader),
		"a truncated capture must be counted as truncated, not parsed")
}

func TestTokenMetrics_ErrorResponseCountedWithoutTokens(t *testing.T) {
	m, reader := newMeteredMiddleware(t)

	_, err := m.Invoke(context.Background(), anthropicInput(500, "application/json", loadFixture(t, "anthropic_messages.json")))
	require.NoError(t, err, "Invoke must not error")

	assert.Empty(t, tokenSums(t, reader), "error responses carry no usage and must not add tokens")
	assert.Equal(t, map[string]int64{resultErrorStatus: 1}, responseSums(t, reader),
		"error responses must still be counted as traffic")
}

func TestTokenMetrics_UnreadableResponseCounted(t *testing.T) {
	m, reader := newMeteredMiddleware(t)

	_, err := m.Invoke(context.Background(), anthropicInput(200, "text/plain", []byte("hello")))
	require.NoError(t, err, "Invoke must not error")

	assert.Empty(t, tokenSums(t, reader), "a body without usage must not add tokens")
	assert.Equal(t, map[string]int64{resultNoUsage: 1}, responseSums(t, reader, attribute.String("mode", modeOther)),
		"a response the parser cannot read must still count, as other/no_usage")
}

func TestTokenMetrics_KindsAreDisjoint(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	tm := newTokenMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))

	// OpenAI: cached tokens are a subset of the input.
	tm.record(context.Background(), response{
		provider: "openai", model: "gpt", mode: modeBuffered, result: resultParsed, cachedInInput: true,
		usage: llm.Usage{InputTokens: 100, CachedInputTokens: 30, OutputTokens: 5},
	})
	// Anthropic: cache reads and writes are beside the input.
	tm.record(context.Background(), response{
		provider: "anthropic", model: "claude", mode: modeBuffered, result: resultParsed,
		usage: llm.Usage{InputTokens: 10, CachedInputTokens: 30, CacheCreationTokens: 20, OutputTokens: 5},
	})

	assert.Equal(t, map[string]int64{"input": 70, "cached_input": 30, "output": 5},
		tokenSums(t, reader, attribute.String("provider", "openai")),
		"OpenAI's cached tokens must be taken out of input")
	assert.Equal(t, map[string]int64{"input": 10, "cached_input": 30, "cache_creation": 20, "output": 5},
		tokenSums(t, reader, attribute.String("provider", "anthropic")),
		"Anthropic's kinds must be counted as reported")
}

func TestTokenMetrics_ModelLabelCapped(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	tm := newTokenMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))

	r := response{provider: "openai", mode: modeBuffered, result: resultParsed, usage: llm.Usage{InputTokens: 1}}
	for i := 0; i < maxModelLabels+10; i++ {
		r.model = fmt.Sprintf("model-%d", i)
		tm.record(context.Background(), r)
	}

	overflow := tokenSums(t, reader, attribute.String("model", modelOverflow))
	assert.Equal(t, int64(10), overflow["input"], "models past the cap must collapse into the overflow label")

	// A model admitted before the cap keeps its own label afterwards.
	r.model = "model-0"
	tm.record(context.Background(), r)
	first := tokenSums(t, reader, attribute.String("model", "model-0"))
	assert.Equal(t, int64(2), first["input"], "already-admitted models must keep their label")
}

func TestMetricsFor_NilMeterIsNotKept(t *testing.T) {
	sharedMetricsMu.Lock()
	saved := sharedMetrics
	sharedMetrics = nil
	sharedMetricsMu.Unlock()
	t.Cleanup(func() {
		sharedMetricsMu.Lock()
		sharedMetrics = saved
		sharedMetricsMu.Unlock()
	})

	// A chain built before builtin.Configure must not pin the noop meter.
	early := metricsFor(nil)
	require.NotNil(t, early, "a nil meter must still yield usable metrics")

	reader := sdkmetric.NewManualReader()
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
	tm := metricsFor(meter)
	assert.NotSame(t, early, tm, "the real meter must get its own instruments")
	assert.Same(t, tm, metricsFor(meter), "the same meter must share one set of instruments")

	tm.record(context.Background(), response{provider: "anthropic", mode: modeBuffered, result: resultParsed})
	assert.Equal(t, map[string]int64{resultParsed: 1}, responseSums(t, reader), "the shared metrics must report on the real meter")

	other := sdkmetric.NewMeterProvider().Meter("other")
	assert.NotSame(t, tm, metricsFor(other), "a new meter must replace the shared instruments")
}

func TestTokenMetrics_ResponseWithoutUsageBlockIsNoUsage(t *testing.T) {
	m, reader := newMeteredMiddleware(t)

	// Valid JSON the parser decodes to zero usage without an error.
	_, err := m.Invoke(context.Background(), anthropicInput(200, "application/json", []byte(`{"id":"msg_abc","type":"message"}`)))
	require.NoError(t, err, "Invoke must not error")

	assert.Empty(t, tokenSums(t, reader), "a body without usage must not add tokens")
	assert.Equal(t, map[string]int64{resultNoUsage: 1}, responseSums(t, reader, attribute.String("mode", modeBuffered)),
		"a JSON body without a usage block must count as no_usage, not parsed")
}

func TestTokenMetrics_TruncatedStreamWithOnlyCacheUsage(t *testing.T) {
	m, reader := newMeteredMiddleware(t)

	body := []byte("event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_abc","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[],"usage":{"input_tokens":0,"output_tokens":0,"cache_read_input_tokens":50,"cache_creation_input_tokens":7}}}` +
		"\n\n")
	in := anthropicInput(200, "text/event-stream", body)
	in.RespBodyTruncated = true

	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "Invoke must not error")

	assert.Equal(t, map[string]int64{"cached_input": 50, "cache_creation": 7}, tokenSums(t, reader),
		"cache counts alone must still count as usage")
	assert.Empty(t, lookupKV(out.Metadata, middleware.KeyLLMCachedInputTokens),
		"the metadata the cost meter reads must keep its rule: no usage keys without input or output")
	assert.Equal(t, map[string]int64{resultTruncated: 1}, responseSums(t, reader), "the response must count as truncated")
}

func TestTokenMetrics_OnlyResponsesWithUsageAdmitModels(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	tm := newTokenMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))
	ctx := context.Background()

	// Names the provider rejects never take a slot.
	for i := 0; i < maxModelLabels+10; i++ {
		tm.record(ctx, response{provider: "anthropic", model: fmt.Sprintf("junk-%d", i), mode: modeBuffered, result: resultErrorStatus})
	}
	assert.Equal(t, map[string]int64{resultErrorStatus: int64(maxModelLabels + 10)},
		responseSums(t, reader, attribute.String("model", modelOverflow)),
		"responses without usage must not admit their model")

	// A served model is admitted, and keeps its label on later errors.
	tm.record(ctx, response{provider: "anthropic", model: "claude", mode: modeBuffered, result: resultParsed, usage: llm.Usage{InputTokens: 1}})
	tm.record(ctx, response{provider: "anthropic", model: "claude", mode: modeBuffered, result: resultErrorStatus})
	assert.Equal(t, map[string]int64{resultParsed: 1, resultErrorStatus: 1},
		responseSums(t, reader, attribute.String("model", "claude")),
		"an admitted model must keep its label on responses without usage")
}

func TestTokenMetrics_ReservedModelNamesAreNotAdmitted(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	tm := newTokenMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))

	usage := llm.Usage{InputTokens: 1}
	tm.record(context.Background(), response{provider: "openai", model: modelUnknown, mode: modeBuffered, result: resultParsed, usage: usage})
	tm.record(context.Background(), response{provider: "openai", model: modelOverflow, mode: modeBuffered, result: resultParsed, usage: usage})

	assert.Equal(t, map[string]int64{resultParsed: 2}, responseSums(t, reader, attribute.String("model", modelOverflow)),
		"a model named after a reserved label must be reported as overflow")
	assert.Empty(t, responseSums(t, reader, attribute.String("model", modelUnknown)),
		"unknown must mean only a request without a model")
	assert.Empty(t, tm.models, "reserved names must not take a slot")
}
