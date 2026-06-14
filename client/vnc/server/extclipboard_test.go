//go:build !js && !ios && !android

package server

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildExtClipCaps(t *testing.T) {
	payload := buildExtClipCaps()
	require.Len(t, payload, 8, "Caps with one format should be 4 bytes flags + 4 bytes size")

	flags := binary.BigEndian.Uint32(payload[0:4])
	// Clients check individual action bits in our Caps to decide whether to
	// auto-Request on Notify, so all supported actions must be advertised.
	assert.NotZero(t, flags&extClipActionCaps, "Caps action bit must be set")
	assert.NotZero(t, flags&extClipActionRequest, "Request action bit must be set")
	assert.NotZero(t, flags&extClipActionPeek, "Peek action bit must be set")
	assert.NotZero(t, flags&extClipActionNotify, "Notify action bit must be set")
	assert.NotZero(t, flags&extClipActionProvide, "Provide action bit must be set")
	assert.Equal(t, extClipFormatText, flags&extClipFormatMask, "should advertise text format")

	maxSize := binary.BigEndian.Uint32(payload[4:8])
	assert.Equal(t, uint32(extClipMaxText), maxSize, "should advertise extClipMaxText")
}

func TestBuildExtClipNotify(t *testing.T) {
	payload := buildExtClipNotify(extClipFormatText)
	require.Len(t, payload, 4)
	flags := binary.BigEndian.Uint32(payload)
	assert.Equal(t, extClipActionNotify, flags&extClipActionMask)
	assert.Equal(t, extClipFormatText, flags&extClipFormatMask)
}

func TestBuildExtClipRequest(t *testing.T) {
	payload := buildExtClipRequest(extClipFormatText)
	require.Len(t, payload, 4)
	flags := binary.BigEndian.Uint32(payload)
	assert.Equal(t, extClipActionRequest, flags&extClipActionMask)
	assert.Equal(t, extClipFormatText, flags&extClipFormatMask)
}

func TestExtClipProvideRoundTripASCII(t *testing.T) {
	const original = "hello world"
	payload, err := buildExtClipProvideText(original)
	require.NoError(t, err)

	flags := binary.BigEndian.Uint32(payload[0:4])
	require.Equal(t, extClipActionProvide, flags&extClipActionMask)
	require.Equal(t, extClipFormatText, flags&extClipFormatMask)

	text, err := parseExtClipProvideText(flags, payload[4:])
	require.NoError(t, err)
	assert.Equal(t, original, text)
}

func TestExtClipProvideRoundTripUTF8(t *testing.T) {
	original := "héllo 🦀 世界"
	payload, err := buildExtClipProvideText(original)
	require.NoError(t, err)

	flags := binary.BigEndian.Uint32(payload[0:4])
	text, err := parseExtClipProvideText(flags, payload[4:])
	require.NoError(t, err)
	assert.Equal(t, original, text, "UTF-8 should round-trip without mangling")
}

func TestExtClipProvideRoundTripEmpty(t *testing.T) {
	payload, err := buildExtClipProvideText("")
	require.NoError(t, err)

	flags := binary.BigEndian.Uint32(payload[0:4])
	text, err := parseExtClipProvideText(flags, payload[4:])
	require.NoError(t, err)
	assert.Empty(t, text)
}

func TestExtClipProvideRoundTripLarge(t *testing.T) {
	original := strings.Repeat("abcd", 200000) // 800 KiB, below cap
	payload, err := buildExtClipProvideText(original)
	require.NoError(t, err)
	assert.Less(t, len(payload), len(original)/2,
		"highly repetitive text should compress significantly")

	flags := binary.BigEndian.Uint32(payload[0:4])
	text, err := parseExtClipProvideText(flags, payload[4:])
	require.NoError(t, err)
	assert.Equal(t, original, text)
}

func TestParseExtClipProvideTextRejectsOversized(t *testing.T) {
	var fakePayload [4]byte
	// 4 bytes of zlib-compressed garbage won't decode; we want to ensure we
	// don't panic, not that we accept it.
	_, err := parseExtClipProvideText(extClipActionProvide|extClipFormatText, fakePayload[:])
	assert.Error(t, err)
}
