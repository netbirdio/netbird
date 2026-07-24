package builtin_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin/cost_meter"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_request_parser"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_response_parser"
)

// TestCostCalculation_ProviderMatrix drives the proxy's real cost pipeline —
// llm_request_parser (provider/model detection + Bedrock/Vertex path
// normalization) → llm_response_parser (usage extraction from realistic wire
// bodies) → cost_meter (pricing) — against the EMBEDDED DEFAULT pricing table
// (no operator override file), and asserts the exact USD amount for every
// metered provider surface.
//
// Expected values are hardcoded dollar amounts derived from the providers'
// published per-million-token prices, NOT recomputed from the pricing table,
// so the test cross-checks three things at once:
//
//  1. the embedded rates match the published prices,
//  2. the per-1k rates are applied to 1k CHUNKS (tokens/1000 × rate) — a
//     missing ÷1000 would inflate every expectation by exactly 1000×,
//  3. the per-provider cache-bucket semantics (OpenAI cached-subset discount
//     vs Anthropic/Bedrock additive read/write buckets) bill correctly.
//
// It includes the field-reported scenario: Bedrock + Claude Sonnet 4.6 with
// 3 input / 1514 output tokens costs $0.022719 bare, and $0.137199 when the
// first request of a session also writes a 30,528-token prompt cache
// (cache_creation_input_tokens — no previous request needed; the write IS the
// first request).
func TestCostCalculation_ProviderMatrix(t *testing.T) {
	// Empty data dir → cost_meter runs on the embedded defaults, exactly like
	// a proxy with no operator pricing override.
	builtin.Configure(context.Background(), t.TempDir(), nil, nil, nil)

	reqMW, err := llm_request_parser.Factory{}.New(nil)
	require.NoError(t, err, "build llm_request_parser")
	respMW, err := llm_response_parser.Factory{}.New(nil)
	require.NoError(t, err, "build llm_response_parser")
	costMW, err := cost_meter.Factory{}.New(nil)
	require.NoError(t, err, "build cost_meter")
	t.Cleanup(func() { _ = costMW.Close() })

	const jsonCT = "application/json"
	const sseCT = "text/event-stream"
	const awsCT = "application/vnd.amazon.eventstream"

	cases := []struct {
		name     string
		url      string
		reqBody  []byte
		respCT   string
		respBody []byte

		wantProvider string
		wantModel    string
		wantCost     float64 // exact expected USD; ignored when wantSkip is set
		wantSkip     string  // expected cost.skipped reason, "" when priced
	}{
		{
			// OpenAI Chat Completions, $0.15/M in + $0.60/M out (gpt-4o-mini):
			// 1000×0.15/1M + 500×0.60/1M.
			name:         "openai chat completions",
			url:          "https://api.openai.com/v1/chat/completions",
			reqBody:      []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`),
			respCT:       jsonCT,
			respBody:     []byte(`{"choices":[{"message":{"content":"pong"}}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}`),
			wantProvider: "openai",
			wantModel:    "gpt-4o-mini",
			wantCost:     0.00045,
		},
		{
			// OpenAI cached prompt tokens are a SUBSET of prompt_tokens and
			// bill at the discount rate; gpt-4o at $2.50/$10 per MTok with
			// $1.25/M cached: 250×2.5/1M + 750×1.25/1M + 500×10/1M.
			name:         "openai cached subset discount",
			url:          "https://api.openai.com/v1/chat/completions",
			reqBody:      []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`),
			respCT:       jsonCT,
			respBody:     []byte(`{"usage":{"prompt_tokens":1000,"completion_tokens":500,"prompt_tokens_details":{"cached_tokens":750}}}`),
			wantProvider: "openai",
			wantModel:    "gpt-4o",
			wantCost:     0.0065625,
		},
		{
			// OpenAI streaming: usage rides the final SSE frame.
			name:         "openai chat SSE stream",
			url:          "https://api.openai.com/v1/chat/completions",
			reqBody:      []byte(`{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`),
			respCT:       sseCT,
			respBody:     sseBody(`{"choices":[{"delta":{"content":"po"}}]}`, `{"choices":[{"delta":{"content":"ng"}}]}`, `{"choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":500}}`, "[DONE]"),
			wantProvider: "openai",
			wantModel:    "gpt-4o-mini",
			wantCost:     0.00045,
		},
		{
			// Mistral speaks the OpenAI shape and is priced under the openai
			// table: mistral-large-latest at $0.50/$1.50 per MTok.
			name:         "mistral via openai shape",
			url:          "https://api.mistral.ai/v1/chat/completions",
			reqBody:      []byte(`{"model":"mistral-large-latest","messages":[{"role":"user","content":"hi"}]}`),
			respCT:       jsonCT,
			respBody:     []byte(`{"usage":{"prompt_tokens":1000,"completion_tokens":1000}}`),
			wantProvider: "openai",
			wantModel:    "mistral-large-latest",
			wantCost:     0.002,
		},
		{
			// The field report, minus caching: Bedrock Claude Sonnet 4.6 at
			// $3/M in + $15/M out. 3×3/1M + 1514×15/1M = $0.022719. Also
			// covers inference-profile normalization: the URL carries the
			// full region-prefixed versioned id.
			name:         "bedrock invoke — reported scenario, no cache",
			url:          "https://bedrock-runtime.eu-central-1.amazonaws.com/model/global.anthropic.claude-sonnet-4-6-20260115-v1:0/invoke",
			reqBody:      []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
			respCT:       jsonCT,
			respBody:     []byte(`{"content":[{"type":"text","text":"pong"}],"usage":{"input_tokens":3,"output_tokens":1514}}`),
			wantProvider: "bedrock",
			wantModel:    "anthropic.claude-sonnet-4-6",
			wantCost:     0.022719,
		},
		{
			// The field report as observed: same request whose FIRST call
			// also wrote a 30,528-token prompt cache. Cache writes bill at
			// 1.25× input ($3.75/M): 0.022719 + 30528×3.75/1M = $0.137199,
			// which renders as the reported $0.1372.
			name:         "bedrock invoke — reported scenario with cache write",
			url:          "https://bedrock-runtime.eu-central-1.amazonaws.com/model/global.anthropic.claude-sonnet-4-6-20260115-v1:0/invoke",
			reqBody:      []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
			respCT:       jsonCT,
			respBody:     []byte(`{"usage":{"input_tokens":3,"output_tokens":1514,"cache_creation_input_tokens":30528,"cache_read_input_tokens":0}}`),
			wantProvider: "bedrock",
			wantModel:    "anthropic.claude-sonnet-4-6",
			wantCost:     0.137199,
		},
		{
			// Same numbers over the InvokeModel event-stream: message_start
			// carries input + cache buckets, message_delta the output count.
			name:         "bedrock invoke stream with cache write",
			url:          "https://bedrock-runtime.eu-central-1.amazonaws.com/model/global.anthropic.claude-sonnet-4-6-20260115-v1:0/invoke-with-response-stream",
			reqBody:      []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
			respCT:       awsCT,
			respBody:     bedrockInvokeStream(t, `{"type":"message_start","message":{"usage":{"input_tokens":3,"output_tokens":1,"cache_creation_input_tokens":30528}}}`, `{"type":"content_block_delta","delta":{"type":"text_delta","text":"pong"}}`, `{"type":"message_delta","usage":{"output_tokens":1514}}`),
			wantProvider: "bedrock",
			wantModel:    "anthropic.claude-sonnet-4-6",
			wantCost:     0.137199,
		},
		{
			// Bedrock Converse reports usage camelCase, cache buckets
			// included (cacheRead/cacheWriteInputTokens). Haiku 4.5 at
			// $1/$5 per MTok, cache read $0.10/M, cache write $1.25/M:
			// 50×1/1M + 100×5/1M + 2000×0.1/1M + 1000×1.25/1M = $0.002.
			name:         "bedrock converse with cache buckets",
			url:          "https://bedrock-runtime.eu-central-1.amazonaws.com/model/eu.anthropic.claude-haiku-4-5-20251001-v1:0/converse",
			reqBody:      []byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`),
			respCT:       jsonCT,
			respBody:     []byte(`{"output":{"message":{"content":[{"text":"pong"}]}},"usage":{"inputTokens":50,"outputTokens":100,"totalTokens":3150,"cacheReadInputTokens":2000,"cacheWriteInputTokens":1000}}`),
			wantProvider: "bedrock",
			wantModel:    "anthropic.claude-haiku-4-5",
			wantCost:     0.002,
		},
		{
			// Same numbers over converse-stream: usage rides the trailing
			// metadata frame.
			name:    "bedrock converse stream with cache buckets",
			url:     "https://bedrock-runtime.eu-central-1.amazonaws.com/model/eu.anthropic.claude-haiku-4-5-20251001-v1:0/converse-stream",
			reqBody: []byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`),
			respCT:  awsCT,
			respBody: bedrockConverseStream(t,
				`{"delta":{"text":"pong"}}`,
				`{"usage":{"inputTokens":50,"outputTokens":100,"totalTokens":3150,"cacheReadInputTokens":2000,"cacheWriteInputTokens":1000}}`,
			),
			wantProvider: "bedrock",
			wantModel:    "anthropic.claude-haiku-4-5",
			wantCost:     0.002,
		},
		{
			// First-party Anthropic Messages API, cache buckets additive:
			// Sonnet 4.6 with 256 in + 200 out + 768 cache read ($0.30/M)
			// + 512 cache write ($3.75/M):
			// 256×3/1M + 200×15/1M + 768×0.3/1M + 512×3.75/1M.
			name:         "anthropic messages with cache buckets",
			url:          "https://api.anthropic.com/v1/messages",
			reqBody:      []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}`),
			respCT:       jsonCT,
			respBody:     []byte(`{"content":[{"type":"text","text":"pong"}],"usage":{"input_tokens":256,"output_tokens":200,"cache_read_input_tokens":768,"cache_creation_input_tokens":512}}`),
			wantProvider: "anthropic",
			wantModel:    "claude-sonnet-4-6",
			wantCost:     0.0059184,
		},
		{
			// Anthropic SSE stream: input + cache from message_start,
			// output from message_delta. Haiku 4.5, 1000 in + 2000 out:
			// 1000×1/1M + 2000×5/1M = $0.011.
			name:         "anthropic SSE stream",
			url:          "https://api.anthropic.com/v1/messages",
			reqBody:      []byte(`{"model":"claude-haiku-4-5","stream":true,"messages":[{"role":"user","content":"hi"}]}`),
			respCT:       sseCT,
			respBody:     sseBody(`{"type":"message_start","message":{"usage":{"input_tokens":1000,"output_tokens":2}}}`, `{"type":"content_block_delta","delta":{"type":"text_delta","text":"pong"}}`, `{"type":"message_delta","usage":{"output_tokens":2000}}`, `{"type":"message_stop"}`),
			wantProvider: "anthropic",
			wantModel:    "claude-haiku-4-5",
			wantCost:     0.011,
		},
		{
			// Kimi's Anthropic-compatible endpoint (the Claude Code setup):
			// kimi-k3 at $3/$15 per MTok under the anthropic table.
			name:         "kimi anthropic shape",
			url:          "https://api.moonshot.ai/anthropic/v1/messages",
			reqBody:      []byte(`{"model":"kimi-k3","messages":[{"role":"user","content":"hi"}]}`),
			respCT:       jsonCT,
			respBody:     []byte(`{"usage":{"input_tokens":1000,"output_tokens":1000}}`),
			wantProvider: "anthropic",
			wantModel:    "kimi-k3",
			wantCost:     0.018,
		},
		{
			// Vertex carries publisher + model in the URL path; the
			// "@version" suffix is stripped and Anthropic-on-Vertex is
			// priced under the anthropic table: 200×3/1M + 100×15/1M.
			name:         "vertex anthropic path-routed",
			url:          "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/anthropic/models/claude-sonnet-4-6@20260115:rawPredict",
			reqBody:      []byte(`{"anthropic_version":"vertex-2023-10-16","messages":[{"role":"user","content":"hi"}]}`),
			respCT:       jsonCT,
			respBody:     []byte(`{"usage":{"input_tokens":200,"output_tokens":100}}`),
			wantProvider: "anthropic",
			wantModel:    "claude-sonnet-4-6",
			wantCost:     0.0021,
		},
		{
			// Gateway-prefixed model ids (Vercel / OpenRouter style) are not
			// in the pricing table: the meter must SKIP, never guess a rate.
			name:         "gateway-prefixed model skips pricing",
			url:          "https://gateway.example.com/v1/chat/completions",
			reqBody:      []byte(`{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`),
			respCT:       jsonCT,
			respBody:     []byte(`{"usage":{"prompt_tokens":1000,"completion_tokens":500}}`),
			wantProvider: "openai",
			wantModel:    "openai/gpt-4o-mini",
			wantSkip:     "unknown_model",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := &middleware.Input{
				Method:  "POST",
				URL:     tc.url,
				Headers: []middleware.KV{{Key: "Content-Type", Value: "application/json"}},
				Body:    tc.reqBody,
			}

			reqOut, err := reqMW.Invoke(context.Background(), in)
			require.NoError(t, err, "request parser")
			in.Metadata = append(in.Metadata, reqOut.Metadata...)

			require.Equal(t, tc.wantProvider, metaKV(in.Metadata, middleware.KeyLLMProvider), "detected provider")
			require.Equal(t, tc.wantModel, metaKV(in.Metadata, middleware.KeyLLMModel), "detected (normalized) model")

			in.Status = 200
			in.RespHeaders = []middleware.KV{{Key: "Content-Type", Value: tc.respCT}}
			in.RespBody = tc.respBody

			respOut, err := respMW.Invoke(context.Background(), in)
			require.NoError(t, err, "response parser")
			in.Metadata = append(in.Metadata, respOut.Metadata...)

			costOut, err := costMW.Invoke(context.Background(), in)
			require.NoError(t, err, "cost meter")

			if tc.wantSkip != "" {
				assert.Equal(t, tc.wantSkip, metaKV(costOut.Metadata, middleware.KeyCostSkipped), "expected cost skip reason")
				assert.Empty(t, metaKV(costOut.Metadata, middleware.KeyCostUSDTotal), "no cost may be emitted on skip")
				return
			}

			raw := metaKV(costOut.Metadata, middleware.KeyCostUSDTotal)
			require.NotEmpty(t, raw, "cost.usd_total must be emitted; skip=%q", metaKV(costOut.Metadata, middleware.KeyCostSkipped))
			got, err := strconv.ParseFloat(raw, 64)
			require.NoError(t, err, "cost must be a float")
			// cost.usd_total is rendered with %.6f, so allow half of the
			// last printed digit on top of float error.
			assert.InDelta(t, tc.wantCost, got, 5.1e-7, "USD cost for %s", tc.name)
		})
	}
}

// metaKV returns the value for key in kvs, or "" when absent.
func metaKV(kvs []middleware.KV, key string) string {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value
		}
	}
	return ""
}

// sseBody renders data frames as a text/event-stream body.
func sseBody(frames ...string) []byte {
	var b bytes.Buffer
	for _, f := range frames {
		b.WriteString("data: ")
		b.WriteString(f)
		b.WriteString("\n\n")
	}
	return b.Bytes()
}

// awsFrame encodes one AWS event-stream frame with the given :event-type.
func awsFrame(t *testing.T, eventType string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := eventstream.NewEncoder()
	require.NoError(t, enc.Encode(&buf, eventstream.Message{
		Headers: eventstream.Headers{{Name: ":event-type", Value: eventstream.StringValue(eventType)}},
		Payload: payload,
	}), "encode event-stream frame")
	return buf.Bytes()
}

// bedrockInvokeStream builds an invoke-with-response-stream body: each
// "chunk" frame wraps a base64-encoded Anthropic stream event.
func bedrockInvokeStream(t *testing.T, events ...string) []byte {
	t.Helper()
	var body bytes.Buffer
	for _, ev := range events {
		wrap, err := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(ev))})
		require.NoError(t, err)
		body.Write(awsFrame(t, "chunk", wrap))
	}
	return body.Bytes()
}

// bedrockConverseStream builds a converse-stream body: N contentBlockDelta
// frames followed by the trailing metadata frame carrying usage.
func bedrockConverseStream(t *testing.T, deltas ...string) []byte {
	t.Helper()
	var body bytes.Buffer
	for i, ev := range deltas {
		eventType := "contentBlockDelta"
		if i == len(deltas)-1 {
			eventType = "metadata"
		}
		body.Write(awsFrame(t, eventType, []byte(ev)))
	}
	return body.Bytes()
}
