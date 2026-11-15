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

func TestServer_AlignedClientOverWebSocket(t *testing.T) {
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
	wantV1, err := messages.MarshalAuthResponse(instanceURL.String())
	require.NoError(t, err)
	wantV2, err := messages.NewEncoder(messages.ProtocolV2, messages.MaxMessageSize).AuthResponse(instanceURL.String())
	require.NoError(t, err)
	v2 := messages.NewEncoder(messages.ProtocolV2, messages.MaxMessageSize)

	// An aligned heartbeat client advertising v2 with a period in the extension area.
	ext, err := messages.MarshalAuthExtension(messages.AuthExtension{PeriodSeconds: 60})
	require.NoError(t, err)
	future := dialRelayWebSocket(t, ctx, addr)
	futureID := messages.HashID("future-client")
	futureAuth, err := v2.Auth(futureID, []byte("future-token"), ext)
	require.NoError(t, err)
	require.NoError(t, future.Write(ctx, websocket.MessageBinary, futureAuth))
	assert.Equal(t, wantV2, readFrame(t, ctx, future), "a v2 client must receive the v2 response")

	legacy := dialRelayWebSocket(t, ctx, addr)
	legacyID := messages.HashID("legacy-client")
	legacyAuth, err := messages.MarshalAuthMsg(legacyID, []byte("legacy-token"))
	require.NoError(t, err)
	require.NoError(t, legacy.Write(ctx, websocket.MessageBinary, legacyAuth))
	assert.Equal(t, wantV1, readFrame(t, ctx, legacy), "a v1 client must receive the response it gets today")

	require.NoError(t, future.Write(ctx, websocket.MessageBinary, v2.Transport(legacyID, []byte("from future"))))
	assertTransportFrame(t, readFrame(t, ctx, legacy), messages.ProtocolV1, futureID, "from future")

	toFuture, err := messages.MarshalTransportMsg(futureID, []byte("from legacy"))
	require.NoError(t, err)
	require.NoError(t, legacy.Write(ctx, websocket.MessageBinary, toFuture))
	assertTransportFrame(t, readFrame(t, ctx, future), messages.ProtocolV2, legacyID, "from legacy")

	// After the response the connection is v2. A frame with another version is dropped and the
	// connection stays usable, which the transport message right after it proves.
	require.NoError(t, future.Write(ctx, websocket.MessageBinary, messages.MarshalHealthcheck()))
	require.NoError(t, future.Write(ctx, websocket.MessageBinary, v2.Transport(legacyID, []byte("after the dropped frame"))))
	assertTransportFrame(t, readFrame(t, ctx, legacy), messages.ProtocolV1, futureID, "after the dropped frame")

	require.NoError(t, future.Write(ctx, websocket.MessageBinary, v2.CloseMsg()))
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
