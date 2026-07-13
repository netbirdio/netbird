package capture

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPcapWriter_GlobalHeader(t *testing.T) {
	var buf bytes.Buffer
	pw := NewPcapWriter(&buf, 0)

	// Header is lazy, so write a dummy packet to trigger it.
	err := pw.WritePacket(time.Now(), []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2})
	require.NoError(t, err)

	data := buf.Bytes()
	require.GreaterOrEqual(t, len(data), 24, "should contain global header")

	assert.Equal(t, uint32(pcapMagic), binary.LittleEndian.Uint32(data[0:4]), "magic number")
	assert.Equal(t, uint16(pcapVersionMaj), binary.LittleEndian.Uint16(data[4:6]), "version major")
	assert.Equal(t, uint16(pcapVersionMin), binary.LittleEndian.Uint16(data[6:8]), "version minor")
	assert.Equal(t, uint32(defaultSnapLen), binary.LittleEndian.Uint32(data[16:20]), "snap length")
	assert.Equal(t, uint32(linkTypeRaw), binary.LittleEndian.Uint32(data[20:24]), "link type")
}

func TestPcapWriter_WritePacket(t *testing.T) {
	var buf bytes.Buffer
	pw := NewPcapWriter(&buf, 100)

	ts := time.Date(2025, 6, 15, 12, 30, 45, 123456000, time.UTC)
	payload := make([]byte, 50)
	for i := range payload {
		payload[i] = byte(i)
	}

	err := pw.WritePacket(ts, payload)
	require.NoError(t, err)

	data := buf.Bytes()[24:] // skip global header
	require.Len(t, data, 16+50, "packet header + payload")

	assert.Equal(t, uint32(ts.Unix()), binary.LittleEndian.Uint32(data[0:4]), "timestamp seconds")
	assert.Equal(t, uint32(123456), binary.LittleEndian.Uint32(data[4:8]), "timestamp microseconds")
	assert.Equal(t, uint32(50), binary.LittleEndian.Uint32(data[8:12]), "included length")
	assert.Equal(t, uint32(50), binary.LittleEndian.Uint32(data[12:16]), "original length")
	assert.Equal(t, payload, data[16:], "packet data")
}

func TestPcapWriter_SnapLen(t *testing.T) {
	var buf bytes.Buffer
	pw := NewPcapWriter(&buf, 10)

	ts := time.Now()
	payload := make([]byte, 50)

	err := pw.WritePacket(ts, payload)
	require.NoError(t, err)

	data := buf.Bytes()[24:]
	assert.Equal(t, uint32(10), binary.LittleEndian.Uint32(data[8:12]), "included length should be truncated")
	assert.Equal(t, uint32(50), binary.LittleEndian.Uint32(data[12:16]), "original length preserved")
	assert.Len(t, data[16:], 10, "only snap_len bytes written")
}
