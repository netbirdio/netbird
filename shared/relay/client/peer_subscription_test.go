package client

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"

	nbRelay "github.com/netbirdio/netbird/shared/relay"
	"github.com/netbirdio/netbird/shared/relay/messages"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockRelayedConn struct {
}

type recordingRelayedConn struct {
	writes [][]byte
}

func (m *mockRelayedConn) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (r *recordingRelayedConn) Write(p []byte) (n int, err error) {
	r.writes = append(r.writes, append([]byte(nil), p...))
	return len(p), nil
}

func TestWaitToBeOnlineAndSubscribe_Success(t *testing.T) {
	peerID := messages.HashID("peer1")
	mockConn := &mockRelayedConn{}
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{}) // discard log output
	sub := NewPeersStateSubscription(logrus.NewEntry(logger), mockConn, messages.MaxMessageSize, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Launch wait in background
	go func() {
		time.Sleep(100 * time.Millisecond)
		sub.OnPeersOnline([]messages.PeerID{peerID})
	}()

	err := sub.WaitToBeOnlineAndSubscribe(ctx, peerID)
	assert.NoError(t, err)
}

func TestWaitToBeOnlineAndSubscribe_Timeout(t *testing.T) {
	peerID := messages.HashID("peer2")
	mockConn := &mockRelayedConn{}
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	sub := NewPeersStateSubscription(logrus.NewEntry(logger), mockConn, messages.MaxMessageSize, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := sub.WaitToBeOnlineAndSubscribe(ctx, peerID)
	assert.Error(t, err)
	assert.Equal(t, context.DeadlineExceeded, err)
}

func TestWaitToBeOnlineAndSubscribe_Duplicate(t *testing.T) {
	peerID := messages.HashID("peer3")
	mockConn := &mockRelayedConn{}
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	sub := NewPeersStateSubscription(logrus.NewEntry(logger), mockConn, messages.MaxMessageSize, nil)

	ctx := context.Background()
	go func() {
		_ = sub.WaitToBeOnlineAndSubscribe(ctx, peerID)

	}()
	time.Sleep(100 * time.Millisecond)
	err := sub.WaitToBeOnlineAndSubscribe(ctx, peerID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already waiting")
}

func TestUnsubscribeStateChange(t *testing.T) {
	peerID := messages.HashID("peer4")
	mockConn := &mockRelayedConn{}
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	sub := NewPeersStateSubscription(logrus.NewEntry(logger), mockConn, messages.MaxMessageSize, nil)

	doneChan := make(chan struct{})
	go func() {
		_ = sub.WaitToBeOnlineAndSubscribe(context.Background(), peerID)
		close(doneChan)
	}()
	time.Sleep(100 * time.Millisecond)

	err := sub.UnsubscribeStateChange([]messages.PeerID{peerID})
	assert.NoError(t, err)

	select {
	case <-doneChan:
	case <-time.After(200 * time.Millisecond):
		// Expected timeout, meaning the subscription was successfully unsubscribed
		t.Errorf("timeout")
	}
}

func TestUnsubscribeStateChange_SplitsByMaxMessageSize(t *testing.T) {
	conn := &recordingRelayedConn{}
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	sub := NewPeersStateSubscription(logrus.NewEntry(logger), conn, nbRelay.QUICMaxDatagramSize, nil)

	peerIDs := make([]messages.PeerID, 100)
	for i := range peerIDs {
		peerIDs[i] = messages.HashID(strconv.Itoa(i))
	}
	require.NoError(t, sub.UnsubscribeStateChange(peerIDs))
	require.Greater(t, len(conn.writes), 1, "the connection limit must force a split")

	var sent []messages.PeerID
	for _, msg := range conn.writes {
		assert.LessOrEqual(t, len(msg), nbRelay.QUICMaxDatagramSize, "message must respect the connection limit")
		chunk, err := messages.UnmarshalUnsubPeerStateMsg(msg)
		require.NoError(t, err)
		sent = append(sent, chunk...)
	}
	assert.Equal(t, peerIDs, sent, "every peer ID must be unsubscribed")
}
