package llm

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The captured prompt is cut from the end downstream, so every parser renders the
// conversation before the standing instructions: a system prompt larger than the cut
// must not push the human's turns out of the access log.
func TestExtractPrompt_InstructionsLast(t *testing.T) {
	tests := []struct {
		name   string
		parser Parser
		body   string
		want   string
	}{
		{
			name:   "anthropic system string",
			parser: AnthropicParser{},
			body:   `{"system":"be brief","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"yes"}]}`,
			want:   "user: hi\nassistant: yes\nsystem: be brief",
		},
		{
			name:   "anthropic system blocks",
			parser: AnthropicParser{},
			body:   `{"system":[{"type":"text","text":"be brief"}],"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`,
			want:   "user: hi\nsystem: be brief",
		},
		{
			name:   "anthropic without system",
			parser: AnthropicParser{},
			body:   `{"messages":[{"role":"user","content":"hi"}]}`,
			want:   "user: hi",
		},
		{
			name:   "openai chat system and developer",
			parser: OpenAIParser{},
			body:   `{"messages":[{"role":"system","content":"be brief"},{"role":"developer","content":"use go"},{"role":"user","content":"ping"},{"role":"assistant","content":"pong"}]}`,
			want:   "user: ping\nassistant: pong\nsystem: be brief\ndeveloper: use go",
		},
		{
			name:   "openai responses developer item",
			parser: OpenAIParser{},
			body:   `{"input":[{"role":"developer","content":"use go"},{"role":"user","content":[{"type":"input_text","text":"ping"}]}]}`,
			want:   "user: ping\ndeveloper: use go",
		},
		{
			name:   "bedrock system parts",
			parser: BedrockParser{},
			body:   `{"system":[{"text":"be brief"}],"messages":[{"role":"user","content":[{"text":"hello"}]}]}`,
			want:   "user: hello\nsystem: be brief",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.parser.ExtractPrompt([]byte(tt.body)), "conversation first, instructions last")
		})
	}
}

// A coding agent's system prompt is larger than any sensible cut. The user's turn has
// to come first so a cut from the end still keeps it.
func TestExtractPrompt_UserTurnSurvivesLargeSystemPrompt(t *testing.T) {
	system := strings.Repeat("instruction ", 8000)
	body := `{"system":"` + system + `","messages":[{"role":"user","content":"fix the flaky test"}]}`

	got := AnthropicParser{}.ExtractPrompt([]byte(body))

	assert.True(t, strings.HasPrefix(got, "user: fix the flaky test\n"), "user turn leads the prompt, got prefix %q", got[:40])
	assert.True(t, strings.HasSuffix(got, "system: "+system), "system prompt trails the conversation")
}
