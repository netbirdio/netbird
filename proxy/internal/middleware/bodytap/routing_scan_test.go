package bodytap

import (
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeBigAnthropicBody builds a request body shaped like Claude Code's:
// a multi-MB "messages" array with the routing fields (model, stream)
// placed AFTER it, which is the ordering that defeats a prefix-only
// capture.
func makeBigAnthropicBody(t *testing.T, model string, stream bool, messagesBytes int) string {
	t.Helper()
	filler := strings.Repeat("x", messagesBytes)
	return fmt.Sprintf(
		`{"max_tokens":64000,"messages":[{"role":"user","content":%q}],"model":%q,"stream":%t}`,
		filler, model, stream,
	)
}

func TestScanRoutingFields_ModelAfterLargeMessages(t *testing.T) {
	body := makeBigAnthropicBody(t, "claude-opus-4-8", true, 3<<20) // 3 MiB messages
	req := httptest.NewRequest("POST", "https://x/v1/messages", strings.NewReader(body))

	model, stream, ok := ScanRoutingFields(req, MaxRoutingScanBytes)
	require.True(t, ok, "model must be recovered even when it follows a multi-MB messages array")
	assert.Equal(t, "claude-opus-4-8", model, "model field must be extracted")
	assert.True(t, stream, "stream field must be extracted")

	// Body must be fully restored for the upstream.
	got, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, body, string(got), "the full request body must be replayed to upstream after scanning")
}

func TestScanRoutingFields_SmallBody(t *testing.T) {
	body := `{"model":"claude-opus-4-8","stream":false,"messages":[]}`
	req := httptest.NewRequest("POST", "https://x/v1/messages", strings.NewReader(body))

	model, stream, ok := ScanRoutingFields(req, MaxRoutingScanBytes)
	require.True(t, ok)
	assert.Equal(t, "claude-opus-4-8", model)
	assert.False(t, stream)

	got, _ := io.ReadAll(req.Body)
	assert.Equal(t, body, string(got), "small bodies must also be restored intact")
}

func TestScanRoutingFields_NoModel(t *testing.T) {
	body := `{"stream":true,"messages":[]}`
	req := httptest.NewRequest("POST", "https://x/v1/messages", strings.NewReader(body))

	_, _, ok := ScanRoutingFields(req, MaxRoutingScanBytes)
	assert.False(t, ok, "ok must be false when no model field is present")

	got, _ := io.ReadAll(req.Body)
	assert.Equal(t, body, string(got), "body must be restored even when model is absent")
}

func TestScanRoutingFields_NotJSON(t *testing.T) {
	body := "this is not json at all"
	req := httptest.NewRequest("POST", "https://x/v1/messages", strings.NewReader(body))

	_, _, ok := ScanRoutingFields(req, MaxRoutingScanBytes)
	assert.False(t, ok, "ok must be false for a non-JSON body")
}

func TestScanRoutingFields_ModelBeyondScanCeiling(t *testing.T) {
	// model sits after 4 MiB of messages but the scan ceiling is 1 MiB:
	// model can't be recovered, yet the full body must still replay.
	body := makeBigAnthropicBody(t, "claude-opus-4-8", true, 4<<20)
	req := httptest.NewRequest("POST", "https://x/v1/messages", strings.NewReader(body))

	_, _, ok := ScanRoutingFields(req, 1<<20)
	assert.False(t, ok, "model beyond the scan ceiling is not recoverable")

	got, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, body, string(got), "the full body must still replay to upstream even when the scan gives up")
}
