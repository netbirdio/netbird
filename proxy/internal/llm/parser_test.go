package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsers_ProviderNames(t *testing.T) {
	parsers := Parsers()
	require.Len(t, parsers, 3, "three built-in parsers expected")

	names := make([]string, 0, len(parsers))
	for _, p := range parsers {
		names = append(names, p.ProviderName())
	}
	assert.Contains(t, names, "openai", "OpenAI parser should be registered")
	assert.Contains(t, names, "anthropic", "Anthropic parser should be registered")
	assert.Contains(t, names, "bedrock", "Bedrock parser should be registered")
}

func TestDetectParser(t *testing.T) {
	cases := []struct {
		name         string
		path         string
		expectedName string
		expectOK     bool
	}{
		{"openai chat", "/v1/chat/completions", "openai", true},
		{"openai prefixed", "/api/v1/chat/completions", "openai", true},
		{"openai responses", "/v1/responses", "openai", true},
		{"anthropic messages", "/v1/messages", "anthropic", true},
		{"anthropic prefixed", "/proxy/v1/messages?query", "anthropic", true},
		{"unknown path", "/healthz", "", false},
		{"empty path", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := DetectParser(tc.path)
			require.Equal(t, tc.expectOK, ok, "detection success mismatch for %q", tc.path)
			if ok {
				assert.Equal(t, tc.expectedName, p.ProviderName(), "provider name mismatch")
			}
		})
	}
}

func TestProviderValues(t *testing.T) {
	assert.Equal(t, Provider(0), ProviderUnknown, "unknown provider is the zero value")
	assert.Equal(t, ProviderOpenAI, OpenAIParser{}.Provider(), "OpenAI parser reports its provider enum")
	assert.Equal(t, ProviderAnthropic, AnthropicParser{}.Provider(), "Anthropic parser reports its provider enum")
}
