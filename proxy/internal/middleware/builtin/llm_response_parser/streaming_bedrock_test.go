package llm_response_parser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/stretchr/testify/require"
)

// bedrockFrame encodes a single AWS event-stream frame with the given
// :event-type header and JSON payload, mirroring what Bedrock sends.
func bedrockFrame(t *testing.T, eventType string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := eventstream.NewEncoder()
	err := enc.Encode(&buf, eventstream.Message{
		Headers: eventstream.Headers{{Name: ":event-type", Value: eventstream.StringValue(eventType)}},
		Payload: payload,
	})
	require.NoError(t, err, "encode event-stream frame")
	return buf.Bytes()
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestAccumulateBedrockStream_Invoke(t *testing.T) {
	// invoke-with-response-stream: each "chunk" frame wraps a base64-encoded
	// Anthropic stream event under {"bytes": ...}.
	events := [][]byte{
		mustJSON(t, map[string]any{"type": "message_start", "message": map[string]any{"usage": map[string]any{"input_tokens": 13}}}),
		mustJSON(t, map[string]any{"type": "content_block_delta", "delta": map[string]any{"type": "text_delta", "text": "po"}}),
		mustJSON(t, map[string]any{"type": "content_block_delta", "delta": map[string]any{"type": "text_delta", "text": "ng"}}),
		mustJSON(t, map[string]any{"type": "message_delta", "usage": map[string]any{"output_tokens": 5}}),
	}
	var body bytes.Buffer
	for _, ev := range events {
		wrap := mustJSON(t, map[string]any{"bytes": base64.StdEncoding.EncodeToString(ev)})
		body.Write(bedrockFrame(t, "chunk", wrap))
	}

	usage, completion := accumulateBedrockStream(body.Bytes())
	require.Equal(t, int64(13), usage.InputTokens, "input tokens from message_start")
	require.Equal(t, int64(5), usage.OutputTokens, "output tokens from message_delta")
	require.Equal(t, int64(18), usage.TotalTokens, "total is additive")
	require.Equal(t, "pong", completion, "text deltas concatenated")
}

func TestAccumulateBedrockStream_Converse(t *testing.T) {
	var body bytes.Buffer
	body.Write(bedrockFrame(t, "contentBlockDelta", mustJSON(t, map[string]any{"delta": map[string]any{"text": "po"}})))
	body.Write(bedrockFrame(t, "contentBlockDelta", mustJSON(t, map[string]any{"delta": map[string]any{"text": "ng"}})))
	body.Write(bedrockFrame(t, "metadata", mustJSON(t, map[string]any{"usage": map[string]any{"inputTokens": 11, "outputTokens": 3, "totalTokens": 14}})))

	usage, completion := accumulateBedrockStream(body.Bytes())
	require.Equal(t, int64(11), usage.InputTokens, "input tokens from metadata frame")
	require.Equal(t, int64(3), usage.OutputTokens, "output tokens from metadata frame")
	require.Equal(t, int64(14), usage.TotalTokens, "total from metadata frame")
	require.Equal(t, "pong", completion, "converse text deltas concatenated")
}

func TestAccumulateBedrockStream_Truncated(t *testing.T) {
	// A body cut mid-frame must not panic; partial usage is returned.
	full := bedrockFrame(t, "metadata", mustJSON(t, map[string]any{"usage": map[string]any{"inputTokens": 11, "outputTokens": 3}}))
	usage, _ := accumulateBedrockStream(full[:len(full)-4])
	require.Zero(t, usage.OutputTokens, "truncated trailing frame is dropped, not panicked on")
}
