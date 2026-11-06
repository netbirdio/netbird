package middleware

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// One request carries the raw prompt from llm_request_parser and its redacted copy
// from llm_guardrail. Both may be the full MaxPromptBytes and must survive the
// per-value, per-middleware and per-request caps together.
func TestAccumulator_FullSizePrompts(t *testing.T) {
	prompt := strings.Repeat("a", MaxPromptBytes)
	acc := NewAccumulator(MaxRequestMetadataBytes)

	raw, rejected := acc.Emit("llm_request_parser",
		[]string{KeyLLMRequestPromptRaw, KeyLLMModel},
		[]KV{{Key: KeyLLMRequestPromptRaw, Value: prompt}, {Key: KeyLLMModel, Value: "test-model"}},
	)
	require.Empty(t, rejected, "raw prompt at MaxPromptBytes is accepted")
	require.Len(t, raw, 2)

	redacted, rejected := acc.Emit("llm_guardrail",
		[]string{KeyLLMRequestPrompt, KeyLLMPolicyDecision},
		[]KV{{Key: KeyLLMRequestPrompt, Value: prompt}, {Key: KeyLLMPolicyDecision, Value: "allow"}},
	)
	require.Empty(t, rejected, "redacted prompt fits next to the raw one")
	require.Len(t, redacted, 2)
	assert.Len(t, redacted[0].Value, MaxPromptBytes, "prompt is kept whole")
}

func TestAccumulator_RejectsValueOverCap(t *testing.T) {
	acc := NewAccumulator(0)

	accepted, rejected := acc.Emit("llm_request_parser",
		[]string{KeyLLMRequestPromptRaw},
		[]KV{{Key: KeyLLMRequestPromptRaw, Value: strings.Repeat("a", MaxMetadataValueBytes+1)}},
	)

	assert.Empty(t, accepted, "value over MaxMetadataValueBytes is dropped")
	require.Len(t, rejected, 1)
	assert.Equal(t, MetadataReasonValueTooLong, rejected[0].Reason, "rejection names the value cap")
}
