//go:build !js

package bind

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

// magicCookieBytes is the STUN magic cookie as it appears on the wire. In a
// WireGuard message the same offset holds the receiver (or sender) index, which is
// a random uint32, so a session can draw exactly this value.
var magicCookieBytes = []byte{0x21, 0x12, 0xA4, 0x42}

const testBufSize = 1500

// wgMsg builds a WireGuard message of the given type and size, with the index field
// at bytes 4:8 set to index.
func wgMsg(msgType uint32, size int, index []byte) []byte {
	pkt := make([]byte, size)
	binary.LittleEndian.PutUint32(pkt[:4], msgType)
	copy(pkt[4:8], index)
	return pkt
}

// intoBuffer copies pkt into a full-size receive buffer, the way the kernel read
// does, so tests see the same buffer/length split as the hot path.
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
		{"keepalive", wgMsgTypeTransport, wgMinMsgSize},
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

// TestIsWireGuardMsg_DisjointFromSTUN locks the invariant the filter relies on: a
// well formed STUN message long enough to be a WireGuard message always has a
// non-zero length field, so it cannot be mistaken for a WireGuard header.
func TestIsWireGuardMsg_DisjointFromSTUN(t *testing.T) {
	types := []stun.MessageType{
		stun.BindingRequest,
		stun.BindingSuccess,
		stun.BindingError,
		{Method: stun.MethodBinding, Class: stun.ClassIndication},
	}

	for _, msgType := range types {
		// Long enough that the length guard is not what makes this pass.
		msg, err := stun.Build(msgType, stun.TransactionID,
			stun.NewUsername("remoteUfrag:localUfrag"), stun.Fingerprint)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(msg.Raw), wgMinMsgSize, "precondition: %s", msgType)
		assert.False(t, isWireGuardMsg(msg.Raw),
			"%s must not look like a WireGuard message", msgType)
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
			assert.Equal(t, tc.want, isWireGuardMsg(tc.pkt), "wrong classification for %s", tc.name)
		})
	}
}

// TestFilterOutStunMessages_IgnoresBytesBeyondPacket guards against classifying on
// buffer contents left over from an earlier, longer packet.
func TestFilterOutStunMessages_IgnoresBytesBeyondPacket(t *testing.T) {
	buf := make([]byte, testBufSize)
	copy(buf[4:8], magicCookieBytes)
	buffers := [][]byte{buf}
	bind := &ICEBind{}

	filtered, err := bind.filterOutStunMessages(buffers, 2, &net.UDPAddr{})
	assert.NoError(t, err)
	assert.False(t, filtered, "a 2 byte packet must not be classified from stale buffer bytes")
}

// TestReceiveFn_ClearsSizeOfConsumedPacket covers the accounting WireGuard relies
// on: sizes is reused across reads, so a slot whose packet was consumed as STUN must
// be reported as empty. Otherwise WireGuard reprocesses the same buffer under the
// previous packet's length, which for a WireGuard-shaped packet means it is handled
// twice.
func TestReceiveFn_ClearsSizeOfConsumedPacket(t *testing.T) {
	conn := listenUDP(t, "udp4", "127.0.0.1:0")
	defer conn.Close()

	recvFn := receiverCreator{setupICEBind(t)}.CreateReceiverFn(
		ipv4.NewPacketConn(conn), conn, false, createMsgPool(),
	)

	msg, err := stun.Build(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
	require.NoError(t, err)

	sender := listenUDP(t, "udp4", "127.0.0.1:0")
	defer sender.Close()
	_, err = sender.WriteTo(msg.Raw, conn.LocalAddr())
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))

	bufs := [][]byte{make([]byte, 1500)}
	// A leftover size from an earlier read, which is what makes the missing reset
	// observable.
	sizes := []int{148}
	eps := make([]wgConn.Endpoint, 1)

	n, err := recvFn(bufs, sizes, eps)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	assert.Zero(t, sizes[0], "consumed STUN packet must not leave a size behind for WireGuard")
}

func TestIsTransportPkg(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
		n    int
		want bool
	}{
		{"transport data with payload", wgMsg(wgMsgTypeTransport, 128, nil), 128, true},
		{"keepalive", wgMsg(wgMsgTypeTransport, wgMinMsgSize, nil), wgMinMsgSize, false},
		{"handshake initiation", wgMsg(wgMsgTypeHandshakeInitiation, 148, nil), 148, false},
		{"stale type bytes beyond packet", wgMsg(wgMsgTypeTransport, 128, nil), 2, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isTransportPkg(intoBuffer(tc.pkt), tc.n),
				"wrong activity classification for %s", tc.name)
		})
	}
}

// TestFilterOutStunMessages_ConsumesSTUNWithWireGuardShapedType covers the one STUN
// encoding whose leading bytes collide with a WireGuard message type: method 0x080 as a
// request encodes to 0x0200, so the type byte reads as a handshake response and the byte
// after it is zero. Only the length check keeps such a message out of WireGuard's hands.
// pion implements no method in that range, so this is a synthetic worst case rather than
// traffic ICE produces.
func TestFilterOutStunMessages_ConsumesSTUNWithWireGuardShapedType(t *testing.T) {
	msg, err := stun.Build(stun.NewType(stun.Method(0x080), stun.ClassRequest), stun.TransactionID)
	require.NoError(t, err)
	require.Equal(t, []byte{0x02, 0x00, 0x00, 0x00}, msg.Raw[:4],
		"precondition: the leading bytes read as a WireGuard message type")

	buffers := intoBuffer(msg.Raw)
	bind := &ICEBind{}

	filtered, err := bind.filterOutStunMessages(buffers, len(msg.Raw), &net.UDPAddr{})
	assert.NoError(t, err)
	assert.True(t, filtered, "STUN message must be consumed despite its WireGuard-shaped type")
}
