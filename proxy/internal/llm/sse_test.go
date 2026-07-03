package llm

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func collectEvents(t *testing.T, r io.Reader) []Event {
	t.Helper()
	s := NewScanner(r)
	var out []Event
	for {
		ev, err := s.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		require.NoError(t, err, "unexpected error scanning SSE")
		out = append(out, ev)
	}
}

func TestSSEScanner_OpenAIFixture(t *testing.T) {
	f, err := os.Open(filepath.Join("fixtures", "openai_stream.txt"))
	require.NoError(t, err, "fixture must be openable")
	defer f.Close()

	events := collectEvents(t, f)
	require.Len(t, events, 4, "expected 4 data frames (3 chunks + [DONE])")

	for _, ev := range events {
		assert.Empty(t, ev.Type, "OpenAI stream uses data-only frames")
	}
	assert.Contains(t, events[2].Data, `"usage"`, "third chunk carries usage block")
	assert.Equal(t, "[DONE]", events[3].Data, "final frame is the OpenAI DONE sentinel")
}

func TestSSEScanner_AnthropicFixture(t *testing.T) {
	f, err := os.Open(filepath.Join("fixtures", "anthropic_stream.txt"))
	require.NoError(t, err, "fixture must be openable")
	defer f.Close()

	events := collectEvents(t, f)
	require.Len(t, events, 7, "expected 7 Anthropic events")

	types := make([]string, 0, len(events))
	for _, ev := range events {
		types = append(types, ev.Type)
	}
	assert.Equal(t, []string{
		"message_start",
		"content_block_start",
		"content_block_delta",
		"content_block_delta",
		"content_block_stop",
		"message_delta",
		"message_stop",
	}, types, "Anthropic event ordering matches fixture")

	var deltaUsage Event
	for _, ev := range events {
		if ev.Type == "message_delta" {
			deltaUsage = ev
			break
		}
	}
	assert.Contains(t, deltaUsage.Data, `"output_tokens":45`, "message_delta carries partial usage")
}

func TestSSEScanner_MultilineData(t *testing.T) {
	raw := "event: ping\ndata: line1\ndata: line2\ndata: line3\n\n"
	events := collectEvents(t, strings.NewReader(raw))

	require.Len(t, events, 1, "one logical event from three data lines")
	assert.Equal(t, "ping", events[0].Type, "event name honored")
	assert.Equal(t, "line1\nline2\nline3", events[0].Data, "data lines joined with newline")
}

func TestSSEScanner_CRLF(t *testing.T) {
	raw := "event: foo\r\ndata: bar\r\n\r\ndata: baz\r\n\r\n"
	events := collectEvents(t, strings.NewReader(raw))

	require.Len(t, events, 2, "CRLF-delimited events recognized")
	assert.Equal(t, "foo", events[0].Type, "first event type preserved")
	assert.Equal(t, "bar", events[0].Data, "first event data preserved")
	assert.Empty(t, events[1].Type, "second event has no event name")
	assert.Equal(t, "baz", events[1].Data, "second event data preserved")
}

func TestSSEScanner_EmptyInput(t *testing.T) {
	s := NewScanner(strings.NewReader(""))
	_, err := s.Next()
	require.ErrorIs(t, err, io.EOF, "empty input yields immediate EOF")
}

func TestSSEScanner_CommentIgnored(t *testing.T) {
	raw := ": this is a comment\ndata: hi\n\n"
	events := collectEvents(t, strings.NewReader(raw))
	require.Len(t, events, 1, "comment line does not emit an event")
	assert.Equal(t, "hi", events[0].Data, "data line honoured after comment")
}

func TestSSEScanner_TrailingWithoutBlankLine(t *testing.T) {
	raw := "event: foo\ndata: bar\n"
	events := collectEvents(t, strings.NewReader(raw))
	require.Len(t, events, 1, "trailing event without blank line still emitted")
	assert.Equal(t, "foo", events[0].Type)
	assert.Equal(t, "bar", events[0].Data)
}

// TestSSEScanner_ManyConsecutiveEmptyLines feeds a stream that is nothing
// but empty lines. The scanner must terminate without panic — empty lines
// alone do not constitute an event and must yield io.EOF.
func TestSSEScanner_ManyConsecutiveEmptyLines(t *testing.T) {
	raw := strings.Repeat("\n", 100)
	s := NewScanner(strings.NewReader(raw))
	_, err := s.Next()
	require.ErrorIs(t, err, io.EOF, "100 empty lines must terminate as EOF without panic")
}

// TestSSEScanner_InterleavedCRLFAndLF mixes \r\n and \n terminators within
// the same event. The scanner normalizes both and must still recover a
// coherent event.
func TestSSEScanner_InterleavedCRLFAndLF(t *testing.T) {
	raw := "event: mix\r\ndata: first\ndata: second\r\n\n"
	events := collectEvents(t, strings.NewReader(raw))
	require.Len(t, events, 1, "mixed line endings must still produce one event")
	assert.Equal(t, "mix", events[0].Type)
	assert.Equal(t, "first\nsecond", events[0].Data, "both data lines joined")
}

// TestSSEScanner_LongSingleDataLine constructs a single data line that
// exceeds the default bufio buffer (64 KiB) but stays under the scanner
// maxLine. The scanner must round-trip the value intact without panicking
// or truncating silently.
func TestSSEScanner_LongSingleDataLine(t *testing.T) {
	big := strings.Repeat("x", 80<<10)
	raw := "data: " + big + "\n\n"
	events := collectEvents(t, strings.NewReader(raw))
	require.Len(t, events, 1, "long single-line event must be emitted")
	assert.Equal(t, big, events[0].Data, "long data preserved")
}

// TestSSEScanner_BinaryGarbageInData validates that non-printable bytes
// inside a data line do not crash the parser. The scanner should either
// round-trip them or return a well-formed error — never panic.
func TestSSEScanner_BinaryGarbageInData(t *testing.T) {
	raw := "data: \x00\x01\x02\xff\xfe\n\n"
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("scanner panicked on binary garbage: %v", r)
		}
	}()
	s := NewScanner(strings.NewReader(raw))
	ev, err := s.Next()
	require.NoError(t, err, "binary bytes in data should not surface as error")
	assert.Equal(t, "\x00\x01\x02\xff\xfe", ev.Data, "binary payload round-trips")
}

// TestSSEScanner_UnknownFieldsIgnored stresses the field parser by sending
// unrecognized field names ("id:", "retry:", "custom:"). They must be
// silently ignored per the SSE spec; the scanner must not panic or emit
// spurious events.
func TestSSEScanner_UnknownFieldsIgnored(t *testing.T) {
	raw := "id: 1\nretry: 5000\ncustom: value\ndata: payload\n\n"
	events := collectEvents(t, strings.NewReader(raw))
	require.Len(t, events, 1, "unknown fields must not spawn extra events")
	assert.Equal(t, "payload", events[0].Data, "data field survives amid unknown fields")
}
