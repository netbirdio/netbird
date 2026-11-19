package server

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/auth/allow"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// TestPeer_InboundFramesKeepBusyPeerConnected reproduces a peer that keeps relaying
// data but never answers a health check, as happens when its reply is lost: on QUIC
// the reply is an unreliable datagram. The relay must count the data as proof of
// life and keep the peer connected for longer than one health check timeout window.
func TestPeer_InboundFramesKeepBusyPeerConnected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		relay := newTestRelay(t, &allow.Auth{})
		alice, _ := acceptPeer(t, relay, "alice")
		bob := newHealthCheckAnsweringConn()
		bobID := acceptPeerOn(t, relay, "bob", bob)

		transport, err := messages.MarshalTransportMsg(bobID, []byte("payload"))
		require.NoError(t, err)

		// The default health check interval is 25s and the timeout window 45s, so three
		// minutes spans several windows in which alice answers no health check.
		const sendFor = 3 * time.Minute
		for elapsed := time.Second; elapsed <= sendFor; elapsed += time.Second {
			alice.deliver(t, transport)
			time.Sleep(time.Second)
			synctest.Wait()
			require.Falsef(t, alice.isClosed(), "a peer sending data must stay connected, closed after %s", elapsed)
		}

		assert.Equal(t, int(sendFor/time.Second), countFrames(bob.frames(), messages.MsgTypeTransport),
			"every transport frame from alice must reach bob")
		assert.Greater(t, countFrames(alice.frames(), messages.MsgTypeHealthCheck), 1,
			"the relay must keep sending health checks to a busy peer")
	})
}

// TestPeer_IdlePeerWithoutHealthCheckReplyIsDisconnected keeps the health check as the
// liveness signal for a peer that sends nothing.
func TestPeer_IdlePeerWithoutHealthCheckReplyIsDisconnected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		relay := newTestRelay(t, &allow.Auth{})
		alice, aliceID := acceptPeer(t, relay, "alice")

		// One timeout window is 45s; the peer must be gone within two.
		time.Sleep(90 * time.Second)
		synctest.Wait()

		assert.True(t, alice.isClosed(), "an idle peer that answers no health check must be disconnected")
		_, ok := relay.store.Peer(aliceID)
		assert.False(t, ok, "the disconnected peer must be removed from the store")
	})
}

// TestPeer_DataStoppingStartsTheTimeout checks that data credits liveness only for the
// window it arrived in: a peer that stops sending and does not answer is disconnected.
func TestPeer_DataStoppingStartsTheTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		relay := newTestRelay(t, &allow.Auth{})
		alice, _ := acceptPeer(t, relay, "alice")
		_, bobID := acceptPeer(t, relay, "bob")

		transport, err := messages.MarshalTransportMsg(bobID, []byte("payload"))
		require.NoError(t, err)
		alice.deliver(t, transport)
		synctest.Wait()

		// Data in the first window covers it; the next two windows carry nothing.
		time.Sleep(3 * 45 * time.Second)
		synctest.Wait()

		assert.True(t, alice.isClosed(), "a peer that stopped sending and answers nothing must be disconnected")
	})
}

// newHealthCheckAnsweringConn returns a scripted connection that echoes every health
// check the relay sends, as a client does.
func newHealthCheckAnsweringConn() *scriptedConn {
	conn := newScriptedConn()
	conn.onWrite = func(frame []byte) {
		if len(frame) >= 2 && messages.MsgType(frame[1]) == messages.MsgTypeHealthCheck {
			conn.reads <- messages.MarshalHealthcheck()
		}
	}
	return conn
}

func acceptPeerOn(t *testing.T, relay *Relay, name string, conn *scriptedConn) messages.PeerID {
	t.Helper()
	peerID := messages.HashID(name)
	auth, err := messages.MarshalAuthMsg(peerID, []byte("token"))
	require.NoError(t, err)

	conn.deliver(t, auth)
	relay.Accept(conn)
	conn.waitFrames(t, 1)
	return peerID
}

func countFrames(frames [][]byte, msgType messages.MsgType) int {
	n := 0
	for _, f := range frames {
		if len(f) >= 2 && messages.MsgType(f[1]) == msgType {
			n++
		}
	}
	return n
}
