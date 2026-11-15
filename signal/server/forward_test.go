package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/signal/proto"
)

// A peer cannot hand another peer a server heartbeat, a going-away or a phase
// request through Send: Signal drops these fields and forwards the rest.
func TestSendStripsServerFields(t *testing.T) {
	const victim = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzI="
	const sender = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzM="
	s := newAlignedTestServer(t)
	stream := connectTestPeer(t, s, victim)

	msg := &proto.EncryptedMessage{
		Key:             sender,
		RemoteKey:       victim,
		Body:            []byte("body"),
		ServerHeartbeat: &proto.ServerHeartbeat{PhaseMillis: 1, GoingAway: true},
		PhaseRequest:    &proto.PhaseRequest{PhaseMillis: 2},
	}
	_, err := s.Send(context.Background(), msg)
	require.NoError(t, err)

	stream.mu.Lock()
	got := append([]*proto.EncryptedMessage(nil), stream.msgs...)
	stream.mu.Unlock()
	require.Len(t, got, 1, "the message must still be forwarded")
	assert.Nil(t, got[0].GetServerHeartbeat(), "a forwarded message must not carry a server heartbeat")
	assert.Nil(t, got[0].GetPhaseRequest(), "a forwarded message must not carry a phase request")
	assert.Equal(t, sender, got[0].GetKey(), "the sender stays")
	assert.Equal(t, []byte("body"), got[0].GetBody(), "the body stays")
	assert.NotNil(t, msg.GetServerHeartbeat(), "the caller's message must not change")

	// The dispatcher hands messages from other Signal instances to the same path.
	s.forwardMessageToPeer(context.Background(), msg)
	stream.mu.Lock()
	got = append([]*proto.EncryptedMessage(nil), stream.msgs...)
	stream.mu.Unlock()
	require.Len(t, got, 2)
	assert.Nil(t, got[1].GetServerHeartbeat(), "a dispatched message must not carry a server heartbeat")
	assert.Nil(t, got[1].GetPhaseRequest(), "a dispatched message must not carry a phase request")
}

// A message for a peer on another Signal instance leaves through the
// dispatcher without the server fields, since that instance may not strip them.
func TestSendStripsServerFieldsBeforeDispatch(t *testing.T) {
	const remote = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMzQ="
	s := newAlignedTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dispatched := make(chan *proto.EncryptedMessage, 1)
	require.NoError(t, s.dispatcher.ListenForMessages(ctx, remote, func(_ context.Context, m *proto.EncryptedMessage) {
		dispatched <- m
	}))

	_, err := s.Send(context.Background(), &proto.EncryptedMessage{
		Key:             "sender",
		RemoteKey:       remote,
		ServerHeartbeat: &proto.ServerHeartbeat{GoingAway: true},
		PhaseRequest:    &proto.PhaseRequest{PhaseMillis: 2},
	})
	require.NoError(t, err)

	select {
	case m := <-dispatched:
		assert.Nil(t, m.GetServerHeartbeat(), "a dispatched message must not carry a server heartbeat")
		assert.Nil(t, m.GetPhaseRequest(), "a dispatched message must not carry a phase request")
	case <-time.After(3 * time.Second):
		t.Fatal("message not dispatched")
	}
}
