package client

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/relay/messages"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockRelayedConn struct {
}

func (m *mockRelayedConn) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func TestWaitToBeOnlineAndSubscribe_Success(t *testing.T) {
	peerID := messages.HashID("peer1")
	mockConn := &mockRelayedConn{}
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{}) // discard log output
	sub := NewPeersStateSubscription(logrus.NewEntry(logger), mockConn, nil)

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
	sub := NewPeersStateSubscription(logrus.NewEntry(logger), mockConn, nil)

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
	sub := NewPeersStateSubscription(logrus.NewEntry(logger), mockConn, nil)

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
	sub := NewPeersStateSubscription(logrus.NewEntry(logger), mockConn, nil)

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
