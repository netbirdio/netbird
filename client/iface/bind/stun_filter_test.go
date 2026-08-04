//go:build !js

package bind

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// magicCookieBytes is the STUN magic cookie as it appears on the wire. In a WireGuard message the
// same offset holds the receiver (or sender) index, which is a random uint32, so a session can draw
// exactly this value.
var magicCookieBytes = []byte{0x21, 0x12, 0xA4, 0x42}

const testBufSize = 1500

// wgMsg builds a WireGuard message of the given type and size, with the index field at bytes 4:8
// set to index.
func wgMsg(msgType uint32, size int, index []byte) []byte {
	pkt := make([]byte, size)
	binary.LittleEndian.PutUint32(pkt[:4], msgType)
	copy(pkt[4:8], index)
	return pkt
}

// intoBuffer copies pkt into a full-size receive buffer, the way the kernel read does, so tests see
// the same buffer/length split as the hot path.
func intoBuffer(pkt []byte) [][]byte {
	buf := make([]byte, testBufSize)
	copy(buf, pkt)
	return [][]byte{buf}
}

func TestFilterOutStunMessages_PassesWireGuardWithCookieShapedIndex(t *testing.T) {
	tests := []struct {
		name    string
		msgType uint32
		size    int
	}{
		{"transport data", wgMsgTypeTransport, 128},
		{"keepalive", wgMsgTypeTransport, wgKeepaliveSize},
		{"handshake initiation", wgMsgTypeHandshakeInitiation, 148},
		{"handshake response", 2, 92},
		{"cookie reply", 3, 64},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt := wgMsg(tc.msgType, tc.size, magicCookieBytes)
			require.True(t, stun.IsMessage(pkt), "precondition: pion sees this as STUN")

			buffers := intoBuffer(pkt)
			bind := &ICEBind{}

			filtered, err := bind.filterOutStunMessages(buffers, tc.size, &net.UDPAddr{})
			assert.NoError(t, err)
			assert.False(t, filtered, "WireGuard message must be handed to WireGuard, not the STUN handler")
			assert.Len(t, buffers[0], testBufSize, "buffer must be left intact for WireGuard")
		})
	}
}

func TestFilterOutStunMessages_FiltersRealSTUNMessage(t *testing.T) {
	msg, err := stun.Build(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
	require.NoError(t, err)

	buffers := intoBuffer(msg.Raw)
	bind := &ICEBind{}

	filtered, err := bind.filterOutStunMessages(buffers, len(msg.Raw), &net.UDPAddr{})
	assert.NoError(t, err)
	assert.True(t, filtered, "STUN message must be consumed by the STUN handler")
	assert.Empty(t, buffers[0], "consumed buffer must be emptied so WireGuard does not see it")
}

// TestIsWireGuardMsg_DisjointFromSTUN locks the invariant the filter relies on: the second byte of a
// STUN message type is never zero, so no STUN message can be mistaken for a WireGuard header.
func TestIsWireGuardMsg_DisjointFromSTUN(t *testing.T) {
	types := []stun.MessageType{
		stun.BindingRequest,
		stun.BindingSuccess,
		stun.BindingError,
		{Method: stun.MethodBinding, Class: stun.ClassIndication},
	}

	for _, msgType := range types {
		msg, err := stun.Build(msgType, stun.TransactionID)
		require.NoError(t, err)
		assert.False(t, isWireGuardMsg(msg.Raw), "%s must not look like a WireGuard message", msgType)
	}
}

func TestIsWireGuardMsg(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"transport data", wgMsg(wgMsgTypeTransport, 128, nil), true},
		{"handshake initiation", wgMsg(wgMsgTypeHandshakeInitiation, 148, nil), true},
		{"unknown type 5", wgMsg(5, 128, nil), false},
		{"type 0", wgMsg(0, 128, nil), false},
		{"non-zero reserved byte", []byte{0x04, 0x00, 0x01, 0x00}, false},
		{"too short", []byte{0x04, 0x00, 0x00}, false},
		{"empty", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isWireGuardMsg(tc.pkt))
		})
	}
}

// TestFilterOutStunMessages_IgnoresBytesBeyondPacket guards against classifying on buffer contents
// left over from an earlier, longer packet.
func TestFilterOutStunMessages_IgnoresBytesBeyondPacket(t *testing.T) {
	buf := make([]byte, testBufSize)
	copy(buf[4:8], magicCookieBytes)
	buffers := [][]byte{buf}
	bind := &ICEBind{}

	filtered, err := bind.filterOutStunMessages(buffers, 2, &net.UDPAddr{})
	assert.NoError(t, err)
	assert.False(t, filtered, "a 2 byte packet must not be classified from stale buffer bytes")
}

func TestIsTransportPkg(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
		n    int
		want bool
	}{
		{"transport data with payload", wgMsg(wgMsgTypeTransport, 128, nil), 128, true},
		{"keepalive", wgMsg(wgMsgTypeTransport, wgKeepaliveSize, nil), wgKeepaliveSize, false},
		{"handshake initiation", wgMsg(wgMsgTypeHandshakeInitiation, 148, nil), 148, false},
		{"stale type bytes beyond packet", wgMsg(wgMsgTypeTransport, 128, nil), 2, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isTransportPkg(intoBuffer(tc.pkt), tc.n))
		})
	}
}
