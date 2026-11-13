package server

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

func TestServer_FutureClientOverWebSocket(t *testing.T) {
	addr := freeAddress(t)
	srv := newTestServer(t, addr)
	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Listen(ListenerConfig{Address: addr})
	}()
	waitForListeners(t, srv, errChan)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	instanceURL := srv.InstanceURL()
	want, err := messages.MarshalAuthResponse(instanceURL.String())
	require.NoError(t, err)

	// A synthetic client advertising a future version with an extension entry this relay does not
	// know: it gets the highest version the relay supports.
	future := dialRelayWebSocket(t, ctx, addr)
	futureID := messages.HashID("future-client")
	futureAuth, err := messages.MarshalAuthEnvelope(3, futureID, []byte("future-token"), []byte{200, 0, 1, 'x'})
	require.NoError(t, err)
	require.NoError(t, future.Write(ctx, websocket.MessageBinary, futureAuth))
	wantV2, err := messages.NewEncoder(messages.ProtocolV2).AuthResponse(instanceURL.String())
	require.NoError(t, err)
	assert.Equal(t, wantV2, readFrame(t, ctx, future), "a future client must receive the v2 response")

	legacy := dialRelayWebSocket(t, ctx, addr)
	legacyID := messages.HashID("legacy-client")
	legacyAuth, err := messages.MarshalAuthMsg(legacyID, []byte("legacy-token"))
	require.NoError(t, err)
	require.NoError(t, legacy.Write(ctx, websocket.MessageBinary, legacyAuth))
	assert.Equal(t, want, readFrame(t, ctx, legacy), "a v1 client must receive the response it gets today")

	toLegacy, err := messages.MarshalTransportMsg(messages.ProtocolV2, legacyID, []byte("from future"))
	require.NoError(t, err)
	require.NoError(t, future.Write(ctx, websocket.MessageBinary, toLegacy))
	assertTransportFrame(t, readFrame(t, ctx, legacy), messages.ProtocolV1, futureID, "from future")

	toFuture, err := messages.MarshalTransportMsg(messages.ProtocolV1, futureID, []byte("from legacy"))
	require.NoError(t, err)
	require.NoError(t, legacy.Write(ctx, websocket.MessageBinary, toFuture))
	assertTransportFrame(t, readFrame(t, ctx, future), messages.ProtocolV2, legacyID, "from legacy")

	// After the response the connection is v2. A frame with another version is dropped and the
	// connection stays usable, which the transport message right after it proves.
	require.NoError(t, future.Write(ctx, websocket.MessageBinary, []byte{1, byte(messages.MsgTypeHealthCheck)}))
	toLegacyAgain, err := messages.MarshalTransportMsg(messages.ProtocolV2, legacyID, []byte("after the dropped frame"))
	require.NoError(t, err)
	require.NoError(t, future.Write(ctx, websocket.MessageBinary, toLegacyAgain))
	assertTransportFrame(t, readFrame(t, ctx, legacy), messages.ProtocolV1, futureID, "after the dropped frame")

	require.NoError(t, future.Write(ctx, websocket.MessageBinary, messages.NewEncoder(messages.ProtocolV2).CloseMsg()))
	require.NoError(t, legacy.Write(ctx, websocket.MessageBinary, messages.MarshalCloseMsg()))
}

func dialRelayWebSocket(t *testing.T, ctx context.Context, addr string) *websocket.Conn {
	t.Helper()
	conn, resp, err := websocket.Dial(ctx, "ws://"+addr+relay.WebSocketURLPath, nil) //nolint:bodyclose
	require.NoError(t, err)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

func readFrame(t *testing.T, ctx context.Context, conn *websocket.Conn) []byte {
	t.Helper()
	msgType, frame, err := conn.Read(ctx)
	require.NoError(t, err)
	require.Equal(t, websocket.MessageBinary, msgType, "relay frames are binary messages")
	return frame
}

func assertTransportFrame(t *testing.T, frame []byte, version messages.ProtocolVersion, sender messages.PeerID, payload string) {
	t.Helper()
	require.GreaterOrEqual(t, len(frame), 2, "a frame must carry the protocol header")
	assert.Equal(t, byte(version), frame[0], "the forwarded frame must carry the destination's version")
	assert.Equal(t, byte(messages.MsgTypeTransport), frame[1], "the forwarded frame must be a transport message")
	id, got, err := messages.UnmarshalTransportMsg(frame)
	require.NoError(t, err)
	assert.Equal(t, sender, *id, "the peer ID must be rewritten to the sender")
	assert.Equal(t, payload, string(got), "the payload must be preserved")
}
