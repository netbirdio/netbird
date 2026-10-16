package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/auth/allow"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

func TestPeer_SkipsUnknownMessageType(t *testing.T) {
	relay := newTestRelay(t, &allow.Auth{})
	alice, _ := acceptPeer(t, relay, "alice")
	_, bobID := acceptPeer(t, relay, "bob")

	alice.deliver(t, []byte{byte(messages.ProtocolV1), 200, 0xDE, 0xAD})
	subscribe, err := messages.MarshalSubPeerStateMsg([]messages.PeerID{bobID})
	require.NoError(t, err)
	alice.deliver(t, subscribe[0])

	// The subscription answer proves the loop survived the unknown frame before it.
	frames := alice.waitFrames(t, 2)
	assert.False(t, alice.isClosed(), "an unknown message type must not close the connection")
	online := frames[1]
	assert.Equal(t, byte(messages.ProtocolV1), online[0], "notifications must carry the connection version")
	assert.Equal(t, byte(messages.MsgTypePeersOnline), online[1], "the subscription must be answered")
	ids, err := messages.UnmarshalPeersOnlineMsg(online)
	require.NoError(t, err)
	assert.Equal(t, []messages.PeerID{bobID}, ids, "the online peer must be reported")
}

func TestPeer_ClosesOnProtocolViolation(t *testing.T) {
	secondAuth, err := messages.MarshalAuthMsg(messages.HashID("alice"), []byte("token"))
	require.NoError(t, err)

	cases := []struct {
		name  string
		frame []byte
	}{
		{"version change mid connection", []byte{2, byte(messages.MsgTypeHealthCheck)}},
		{"version zero", []byte{0, byte(messages.MsgTypeHealthCheck)}},
		{"reserved hello type", []byte{byte(messages.ProtocolV1), byte(messages.MsgTypeHello)}},
		{"server-only peers online type", []byte{byte(messages.ProtocolV1), byte(messages.MsgTypePeersOnline)}},
		{"auth after authentication", secondAuth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay := newTestRelay(t, &allow.Auth{})
			conn, peerID := acceptPeer(t, relay, "alice")

			conn.deliver(t, tc.frame)

			conn.waitClosed(t)
			assert.Len(t, conn.frames(), 1, "only the auth response may be written")
			assert.Eventually(t, func() bool {
				_, ok := relay.store.Peer(peerID)
				return !ok
			}, testWaitTimeout, 5*time.Millisecond, "the peer must be removed from the store")
		})
	}
}

func TestPeer_ForwardsTransportWithSenderAndDestinationVersion(t *testing.T) {
	relay := newTestRelay(t, &allow.Auth{})
	alice, aliceID := acceptPeer(t, relay, "alice")
	bob, bobID := acceptPeer(t, relay, "bob")

	payload := []byte("hello bob")
	transport, err := messages.MarshalTransportMsg(bobID, payload)
	require.NoError(t, err)
	alice.deliver(t, transport)

	frames := bob.waitFrames(t, 2)
	forwarded := frames[1]
	assert.Equal(t, byte(messages.ProtocolV1), forwarded[0], "the forwarded frame must carry the destination's version")
	assert.Equal(t, byte(messages.MsgTypeTransport), forwarded[1], "the forwarded frame must stay a transport message")
	senderID, gotPayload, err := messages.UnmarshalTransportMsg(forwarded)
	require.NoError(t, err)
	assert.Equal(t, aliceID, *senderID, "the peer ID must be rewritten to the sender")
	assert.Equal(t, payload, gotPayload, "the payload must be preserved")
	assert.False(t, alice.isClosed(), "the sender must stay connected")
}

func TestPeer_GracefulCloseCarriesConnectionVersion(t *testing.T) {
	relay := newTestRelay(t, &allow.Auth{})
	conn, _ := acceptPeer(t, relay, "alice")

	relay.Shutdown(context.Background())

	frames := conn.waitFrames(t, 2)
	assert.Equal(t, messages.NewEncoder(messages.ProtocolV1).CloseMsg(), frames[1], "the close message must carry the connection version")
	assert.True(t, conn.isClosed(), "the connection must be closed after the close message")
}
