package llm_response_parser

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/netbirdio/netbird/proxy/internal/llm"
)

// Token kinds reported on proxy.llm.tokens_total{kind=...}. The kinds
// are disjoint for every provider, so their sum is everything the model
// read and wrote: "input" is the prompt not served from or written to
// the provider's cache, "cached_input" the prompt read from it,
// "cache_creation" the prompt written to it, and "output" the
// completion. OpenAI reports its cached tokens inside its input; they
// are taken out of "input" here (see tokenMetrics.record).
const (
	tokenKindInput         = "input"
	tokenKindOutput        = "output"
	tokenKindCachedInput   = "cached_input"
	tokenKindCacheCreation = "cache_creation"
)

// Response modes reported on proxy.llm.responses_total{mode=...}.
const (
	modeBuffered  = "buffered"
	modeStreaming = "streaming"
	modeOther     = "other"
)

// Response results reported on proxy.llm.responses_total{result=...}.
// Every response from a recognised provider is counted under one, so
// the counter shows traffic whether or not its usage could be read.
const (
	// resultParsed: usage was read from a complete body.
	resultParsed = "parsed"
	// resultTruncated: the capture hit its byte cap before the body
	// ended. Whatever usage the prefix held is still counted, so the
	// tokens of these responses are a lower bound: streams report
	// output (and OpenAI all usage) at the end.
	resultTruncated = "truncated"
	// resultNoUsage: a complete, successful body with no usage the
	// parser could read (an unhandled content type or shape).
	resultNoUsage = "no_usage"
	// resultErrorStatus: the upstream answered with a status >= 400.
	resultErrorStatus = "error_status"
)

// maxModelLabels caps the number of distinct models this process will
// report under their own name; on top of them come modelOverflow and
// modelUnknown. llm.model is taken from the client's request body, so
// without a cap any caller could mint unbounded series. A model is
// admitted only by a response that carried usage, which shows the
// provider served it: a caller cannot use up the cap with names the
// provider rejects. Models beyond the cap, and models not yet admitted
// on responses without usage, are reported as modelOverflow.
const (
	maxModelLabels = 64
	modelOverflow  = "other"
	modelUnknown   = "unknown"
)

// tokenMetrics holds the process-wide LLM counters. Middleware
// instances are built per chain, but the instruments and the
// model-label guard must be shared so the cap is per process, not per
// chain.
type tokenMetrics struct {
	meter     metric.Meter
	tokens    metric.Int64Counter
	responses metric.Int64Counter

	mu     sync.Mutex
	models map[string]struct{}
}

var (
	sharedMetrics   *tokenMetrics
	sharedMetricsMu sync.Mutex
)

// metricsFor returns the process-wide metrics for meter, registering the
// instruments on it the first time it is seen. A nil meter (tests, or a
// chain built before builtin.Configure) gets noop instruments that are
// not kept, so a later call with the real meter still registers them;
// a different meter (Configure called again) replaces the shared set.
func metricsFor(meter metric.Meter) *tokenMetrics {
	if meter == nil {
		return newTokenMetrics(nil)
	}
	sharedMetricsMu.Lock()
	defer sharedMetricsMu.Unlock()
	if sharedMetrics == nil || sharedMetrics.meter != meter {
		sharedMetrics = newTokenMetrics(meter)
	}
	return sharedMetrics
}

func newTokenMetrics(meter metric.Meter) *tokenMetrics {
	if meter == nil {
		meter = noop.NewMeterProvider().Meter("proxy.llm.noop")
	}
	tm := &tokenMetrics{meter: meter, models: make(map[string]struct{})}
	fallback := noop.NewMeterProvider().Meter("proxy.llm.noop")

	var err error
	tm.tokens, err = meter.Int64Counter(
		"proxy.llm.tokens_total",
		metric.WithUnit("{token}"),
		metric.WithDescription("LLM tokens reported by upstream providers, by account, provider, model and kind"),
	)
	if err != nil {
		tm.tokens, _ = fallback.Int64Counter("proxy.llm.tokens_total")
	}

	tm.responses, err = meter.Int64Counter(
		"proxy.llm.responses_total",
		metric.WithUnit("1"),
		metric.WithDescription("LLM responses from upstream providers, by account, provider, model, mode and whether their usage could be read"),
	)
	if err != nil {
		tm.responses, _ = fallback.Int64Counter("proxy.llm.responses_total")
	}
	return tm
}

// modelLabel returns model if it is already tracked, or if admit is set
// and there is room under the cap; modelOverflow otherwise.
func (tm *tokenMetrics) modelLabel(model string, admit bool) string {
	if model == "" {
		return modelUnknown
	}
	// The reserved labels are never a model's own, so they stay
	// unambiguous even if an upstream serves a model by that name.
	if model == modelOverflow || model == modelUnknown {
		return modelOverflow
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if _, ok := tm.models[model]; ok {
		return model
	}
	if !admit || len(tm.models) >= maxModelLabels {
		return modelOverflow
	}
	tm.models[model] = struct{}{}
	return model
}

// response is one upstream response as the counters see it.
type response struct {
	accountID string
	provider  string
	model     string
	mode      string
	result    string
	usage     llm.Usage
	// cachedInInput says the provider's input count already includes
	// its cached tokens (OpenAI), so they are taken out of "input".
	cachedInInput bool
}

// record counts one response and adds its usage to the token counter.
func (tm *tokenMetrics) record(ctx context.Context, r response) {
	if tm == nil {
		return
	}
	base := []attribute.KeyValue{
		attribute.String("account_id", r.accountID),
		attribute.String("provider", r.provider),
		attribute.String("model", tm.modelLabel(r.model, hasUsage(r.usage))),
	}
	with := func(kv ...attribute.KeyValue) metric.AddOption {
		attrs := make([]attribute.KeyValue, 0, len(base)+len(kv))
		return metric.WithAttributes(append(append(attrs, base...), kv...)...)
	}

	tm.responses.Add(ctx, 1, with(
		attribute.String("mode", r.mode),
		attribute.String("result", r.result),
	))

	input := r.usage.InputTokens
	if r.cachedInInput {
		input -= r.usage.CachedInputTokens
	}
	add := func(kind string, n int64) {
		if n <= 0 {
			return
		}
		tm.tokens.Add(ctx, n, with(attribute.String("kind", kind)))
	}
	add(tokenKindInput, input)
	add(tokenKindOutput, r.usage.OutputTokens)
	add(tokenKindCachedInput, r.usage.CachedInputTokens)
	add(tokenKindCacheCreation, r.usage.CacheCreationTokens)
}
