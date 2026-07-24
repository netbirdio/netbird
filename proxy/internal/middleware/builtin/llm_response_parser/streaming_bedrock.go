package llm_response_parser

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"

	"github.com/netbirdio/netbird/proxy/internal/llm"
)

// bedrockEventTypeHeader names each AWS event-stream frame's event type.
const bedrockEventTypeHeader = ":event-type"

// accumulateBedrockStream decodes the AWS binary event-stream returned by
// Bedrock's streaming endpoints and folds it into running usage/completion.
// Two framings are handled:
//   - InvokeModel (invoke-with-response-stream): each "chunk" frame's payload is
//     {"bytes":"<base64>"} wrapping a vendor-native (Anthropic) stream event.
//   - Converse (converse-stream): native frames (contentBlockDelta, metadata, …)
//     whose payload JSON carries text deltas and a final usage block.
//
// A truncated stream (cut at the capture cap) decodes best-effort: frames up to
// the cut are applied and the partial usage is returned.
func accumulateBedrockStream(body []byte) (llm.Usage, string) {
	var (
		usage      llm.Usage
		completion strings.Builder
	)
	dec := eventstream.NewDecoder()
	r := bytes.NewReader(body)
	for {
		msg, err := dec.Decode(r, nil)
		if err != nil {
			break // EOF or a partial trailing frame — return what we have.
		}
		eventType := ""
		if v := msg.Headers.Get(bedrockEventTypeHeader); v != nil {
			eventType = v.String()
		}
		if eventType == "chunk" {
			applyBedrockInvokeChunk(msg.Payload, &usage, &completion)
			continue
		}
		applyConverseStreamEvent(eventType, msg.Payload, &usage, &completion)
	}
	if usage.TotalTokens == 0 && (usage.InputTokens > 0 || usage.OutputTokens > 0) {
		usage.TotalTokens = usage.InputTokens + usage.OutputTokens + usage.CachedInputTokens + usage.CacheCreationTokens
	}
	return usage, completion.String()
}

// applyBedrockInvokeChunk decodes an InvokeModel stream "chunk" frame
// ({"bytes":"<base64 anthropic event>"}) and folds the wrapped Anthropic event
// into usage/completion via the shared accumulator.
func applyBedrockInvokeChunk(payload []byte, usage *llm.Usage, completion *strings.Builder) {
	var wrap struct {
		Bytes []byte `json:"bytes"` // base64 string — encoding/json decodes it
	}
	if err := json.Unmarshal(payload, &wrap); err != nil || len(wrap.Bytes) == 0 {
		return
	}
	var ev anthropicStreamEvent
	if err := json.Unmarshal(wrap.Bytes, &ev); err != nil {
		return
	}
	applyAnthropicStreamEvent(ev.Type, ev, usage, completion)
}

// converseStreamEvent captures the Converse stream frames carrying completion
// text (contentBlockDelta) and the final token usage (metadata). The cache
// buckets are additive to inputTokens, same as the InvokeModel snake_case
// shape (AWS names the write bucket cacheWriteInputTokens).
type converseStreamEvent struct {
	Delta *struct {
		Text string `json:"text"`
	} `json:"delta"`
	Usage *struct {
		InputTokens      int64 `json:"inputTokens"`
		OutputTokens     int64 `json:"outputTokens"`
		TotalTokens      int64 `json:"totalTokens"`
		CacheReadTokens  int64 `json:"cacheReadInputTokens"`
		CacheWriteTokens int64 `json:"cacheWriteInputTokens"`
	} `json:"usage"`
}

// applyConverseStreamEvent folds one native Converse stream frame into the
// running usage/completion: contentBlockDelta carries assistant text, and the
// trailing metadata frame carries the final usage block.
func applyConverseStreamEvent(eventType string, payload []byte, usage *llm.Usage, completion *strings.Builder) {
	var ev converseStreamEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return
	}
	switch eventType {
	case "contentBlockDelta":
		if ev.Delta != nil {
			completion.WriteString(ev.Delta.Text)
		}
	case "metadata":
		if ev.Usage != nil {
			if ev.Usage.InputTokens > 0 {
				usage.InputTokens = ev.Usage.InputTokens
			}
			if ev.Usage.OutputTokens > 0 {
				usage.OutputTokens = ev.Usage.OutputTokens
			}
			if ev.Usage.TotalTokens > 0 {
				usage.TotalTokens = ev.Usage.TotalTokens
			}
			if ev.Usage.CacheReadTokens > 0 {
				usage.CachedInputTokens = ev.Usage.CacheReadTokens
			}
			if ev.Usage.CacheWriteTokens > 0 {
				usage.CacheCreationTokens = ev.Usage.CacheWriteTokens
			}
		}
	}
}
