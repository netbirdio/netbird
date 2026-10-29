package capture

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSession_PcapOutput(t *testing.T) {
	var buf bytes.Buffer
	sess, err := NewSession(Options{
		Output:  &buf,
		BufSize: 16,
	})
	require.NoError(t, err)

	pkt := buildIPv4Packet(t,
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		protoTCP, 12345, 443)

	sess.Offer(pkt, true)
	sess.Stop()

	data := buf.Bytes()
	require.Greater(t, len(data), 24, "should have global header + at least one packet")

	// Verify global header
	assert.Equal(t, uint32(pcapMagic), binary.LittleEndian.Uint32(data[0:4]))
	assert.Equal(t, uint32(linkTypeRaw), binary.LittleEndian.Uint32(data[20:24]))

	// Verify packet record
	pktData := data[24:]
	inclLen := binary.LittleEndian.Uint32(pktData[8:12])
	assert.Equal(t, uint32(len(pkt)), inclLen)

	stats := sess.Stats()
	assert.Equal(t, int64(1), stats.Packets)
	assert.Equal(t, int64(len(pkt)), stats.Bytes)
	assert.Equal(t, int64(0), stats.Dropped)
}

func TestSession_TextOutput(t *testing.T) {
	var buf bytes.Buffer
	sess, err := NewSession(Options{
		TextOutput: &buf,
		BufSize:    16,
	})
	require.NoError(t, err)

	pkt := buildIPv4Packet(t,
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		protoTCP, 12345, 443)

	sess.Offer(pkt, false)
	sess.Stop()

	output := buf.String()
	assert.Contains(t, output, "TCP")
	assert.Contains(t, output, "10.0.0.1")
	assert.Contains(t, output, "10.0.0.2")
	assert.Contains(t, output, "443")
	assert.Contains(t, output, "[IN   TCP]")
}

func TestSession_Filter(t *testing.T) {
	var buf bytes.Buffer
	sess, err := NewSession(Options{
		Output:  &buf,
		Matcher: &Filter{Port: 443},
	})
	require.NoError(t, err)

	pktMatch := buildIPv4Packet(t,
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		protoTCP, 12345, 443)
	pktNoMatch := buildIPv4Packet(t,
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		protoTCP, 12345, 80)

	sess.Offer(pktMatch, true)
	sess.Offer(pktNoMatch, true)
	sess.Stop()

	stats := sess.Stats()
	assert.Equal(t, int64(1), stats.Packets, "only matching packet should be captured")
}

func TestSession_StopIdempotent(t *testing.T) {
	var buf bytes.Buffer
	sess, err := NewSession(Options{Output: &buf})
	require.NoError(t, err)

	sess.Stop()
	sess.Stop() // should not panic or deadlock
}

func TestSession_OfferAfterStop(t *testing.T) {
	var buf bytes.Buffer
	sess, err := NewSession(Options{Output: &buf})
	require.NoError(t, err)
	sess.Stop()

	pkt := buildIPv4Packet(t,
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		protoTCP, 12345, 443)
	sess.Offer(pkt, true) // should not panic

	assert.Equal(t, int64(0), sess.Stats().Packets)
}

func TestSession_Done(t *testing.T) {
	var buf bytes.Buffer
	sess, err := NewSession(Options{Output: &buf})
	require.NoError(t, err)

	select {
	case <-sess.Done():
		t.Fatal("Done should not be closed before Stop")
	default:
	}

	sess.Stop()

	select {
	case <-sess.Done():
	case <-time.After(time.Second):
		t.Fatal("Done should be closed after Stop")
	}
}

func TestSession_RequiresOutput(t *testing.T) {
	_, err := NewSession(Options{})
	assert.Error(t, err)
}
