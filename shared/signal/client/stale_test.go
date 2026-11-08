package client

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/shared/signal/proto"
)

type countingSender struct {
	sends atomic.Int32
}

func (s *countingSender) Send(*proto.EncryptedMessage) error {
	s.sends.Add(1)
	return nil
}

func shortStaleProbe(t *testing.T) {
	t.Helper()
	oldTimeout, oldPoll := staleProbeTimeout, staleProbePoll
	staleProbeTimeout, staleProbePoll = 300*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { staleProbeTimeout, staleProbePoll = oldTimeout, oldPoll })
}

// newStaleProbeClient returns a client dialed to a real Signal server with no
// stream open, so the unary self-probe goes out but nothing comes back.
func newStaleProbeClient(t *testing.T) (*GrpcClient, context.Context) {
	t.Helper()
	addr := startTestSignalServer(t)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c, err := NewClient(ctx, addr, key, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c, ctx
}

// A stale probe that gets no frame back within the wall-time budget cancels
// the stream so the retry loop reconnects.
func TestStaleProbeTimeoutReconnects(t *testing.T) {
	shortStaleProbe(t)
	c, ctx := newStaleProbeClient(t)
	sender := &countingSender{}

	var cancelled atomic.Bool
	streamCtx, cancelStream := context.WithCancel(ctx)
	t.Cleanup(cancelStream)
	done := make(chan struct{})
	go func() {
		c.staleProbe(streamCtx, func() { cancelled.Store(true); cancelStream() }, sender)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stale probe did not finish")
	}
	assert.True(t, cancelled.Load(), "an unanswered probe must cancel the stream")
	assert.True(t, c.receiveStalled.Load(), "an unanswered probe must mark the stream stalled")
	assert.Eventually(t, func() bool { return sender.sends.Load() == 1 }, time.Second, 5*time.Millisecond,
		"the probe must write once on the stream")
}

// Any frame received after the probe went out is the answer: the stream stays.
func TestStaleProbeAnsweredKeepsStream(t *testing.T) {
	shortStaleProbe(t)
	c, ctx := newStaleProbeClient(t)
	sender := &countingSender{}

	var cancelled atomic.Bool
	streamCtx, cancelStream := context.WithCancel(ctx)
	t.Cleanup(cancelStream)
	go func() {
		time.Sleep(50 * time.Millisecond)
		c.lastFrameAt.Store(time.Now().UnixNano())
	}()
	done := make(chan struct{})
	go func() {
		c.staleProbe(streamCtx, func() { cancelled.Store(true) }, sender)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stale probe did not finish")
	}
	assert.False(t, cancelled.Load(), "an answered probe must not cancel the stream")
	assert.False(t, c.receiveStalled.Load(), "an answered probe must not mark the stream stalled")
}

// A frame from before the probe is not an answer.
func TestStaleProbeIgnoresOlderFrame(t *testing.T) {
	shortStaleProbe(t)
	c, ctx := newStaleProbeClient(t)
	c.lastFrameAt.Store(time.Now().Add(-time.Second).UnixNano())

	var cancelled atomic.Bool
	streamCtx, cancelStream := context.WithCancel(ctx)
	t.Cleanup(cancelStream)
	c.staleProbe(streamCtx, func() { cancelled.Store(true) }, &countingSender{})
	assert.True(t, cancelled.Load(), "a frame older than the probe must not count as the answer")
}

// The receive loop stamps the wall time of every frame, heartbeat included.
func TestReceiveStampsLastFrame(t *testing.T) {
	c := newHeartbeatTestClient(t)
	before := time.Now().UnixNano()
	err := c.receive(&fakeConnectStream{msgs: []*proto.EncryptedMessage{heartbeatFrame()}})
	require.Error(t, err, "the fake stream ends with EOF")
	assert.GreaterOrEqual(t, c.lastFrameAt.Load(), before, "a heartbeat frame must stamp lastFrameAt")
}
