package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
)

func newTestServer() *Server {
	ctx := internal.CtxInitState(context.Background())
	return &Server{
		rootCtx:        ctx,
		statusRecorder: peer.NewRecorder(""),
	}
}

func TestNotifyOSLifecycle_WakeUp_SkipsWhenNotSleepTriggered(t *testing.T) {
	s := newTestServer()

	// sleepTriggeredDown is false by default
	assert.False(t, s.sleepTriggeredDown.Load())

	resp, err := s.NotifyOSLifecycle(context.Background(), &proto.OSLifecycleRequest{
		Type: proto.OSLifecycleRequest_WAKEUP,
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, s.sleepTriggeredDown.Load(), "flag should remain false")
}

func TestNotifyOSLifecycle_Sleep_SkipsWhenStatusIdle(t *testing.T) {
	s := newTestServer()

	state := internal.CtxGetState(s.rootCtx)
	state.Set(internal.StatusIdle)

	resp, err := s.NotifyOSLifecycle(context.Background(), &proto.OSLifecycleRequest{
		Type: proto.OSLifecycleRequest_SLEEP,
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, s.sleepTriggeredDown.Load(), "flag should remain false when status is Idle")
}

func TestNotifyOSLifecycle_Sleep_SkipsWhenStatusNeedsLogin(t *testing.T) {
	s := newTestServer()

	state := internal.CtxGetState(s.rootCtx)
	state.Set(internal.StatusNeedsLogin)

	resp, err := s.NotifyOSLifecycle(context.Background(), &proto.OSLifecycleRequest{
		Type: proto.OSLifecycleRequest_SLEEP,
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, s.sleepTriggeredDown.Load(), "flag should remain false when status is NeedsLogin")
}

func TestNotifyOSLifecycle_Sleep_SetsFlag_WhenConnecting(t *testing.T) {
	s := newTestServer()

	state := internal.CtxGetState(s.rootCtx)
	state.Set(internal.StatusConnecting)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.actCancel = cancel

	resp, err := s.NotifyOSLifecycle(ctx, &proto.OSLifecycleRequest{
		Type: proto.OSLifecycleRequest_SLEEP,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp, "handleSleep returns not nil response on success")
	assert.True(t, s.sleepTriggeredDown.Load(), "flag should be set after sleep when connecting")
}

func TestNotifyOSLifecycle_Sleep_SetsFlag_WhenConnected(t *testing.T) {
	s := newTestServer()

	state := internal.CtxGetState(s.rootCtx)
	state.Set(internal.StatusConnected)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.actCancel = cancel

	resp, err := s.NotifyOSLifecycle(ctx, &proto.OSLifecycleRequest{
		Type: proto.OSLifecycleRequest_SLEEP,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp, "handleSleep returns not nil response on success")
	assert.True(t, s.sleepTriggeredDown.Load(), "flag should be set after sleep when connected")
}

func TestNotifyOSLifecycle_WakeUp_ResetsFlag(t *testing.T) {
	s := newTestServer()

	// Manually set the flag to simulate prior sleep down
	s.sleepTriggeredDown.Store(true)

	// WakeUp will try to call Up which fails without proper setup, but flag should reset first
	_, _ = s.NotifyOSLifecycle(context.Background(), &proto.OSLifecycleRequest{
		Type: proto.OSLifecycleRequest_WAKEUP,
	})

	assert.False(t, s.sleepTriggeredDown.Load(), "flag should be reset after WakeUp attempt")
}

func TestNotifyOSLifecycle_MultipleWakeUpCalls(t *testing.T) {
	s := newTestServer()

	// First wakeup without prior sleep - should be no-op
	resp, err := s.NotifyOSLifecycle(context.Background(), &proto.OSLifecycleRequest{
		Type: proto.OSLifecycleRequest_WAKEUP,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, s.sleepTriggeredDown.Load())

	// Simulate prior sleep
	s.sleepTriggeredDown.Store(true)

	// First wakeup after sleep - should reset flag
	_, _ = s.NotifyOSLifecycle(context.Background(), &proto.OSLifecycleRequest{
		Type: proto.OSLifecycleRequest_WAKEUP,
	})
	assert.False(t, s.sleepTriggeredDown.Load())

	// Second wakeup - should be no-op
	resp, err = s.NotifyOSLifecycle(context.Background(), &proto.OSLifecycleRequest{
		Type: proto.OSLifecycleRequest_WAKEUP,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, s.sleepTriggeredDown.Load())
}

func TestHandleWakeUp_SkipsWhenFlagFalse(t *testing.T) {
	s := newTestServer()

	resp, err := s.handleWakeUp(context.Background())

	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestHandleWakeUp_ResetsFlagBeforeUp(t *testing.T) {
	s := newTestServer()
	s.sleepTriggeredDown.Store(true)

	// Even if Up fails, flag should be reset
	_, _ = s.handleWakeUp(context.Background())

	assert.False(t, s.sleepTriggeredDown.Load(), "flag must be reset before calling Up")
}

func TestHandleSleep_SkipsForNonActiveStates(t *testing.T) {
	tests := []struct {
		name   string
		status internal.StatusType
	}{
		{"Idle", internal.StatusIdle},
		{"NeedsLogin", internal.StatusNeedsLogin},
		{"LoginFailed", internal.StatusLoginFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer()
			state := internal.CtxGetState(s.rootCtx)
			state.Set(tt.status)

			resp, err := s.handleSleep(context.Background())

			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.False(t, s.sleepTriggeredDown.Load())
		})
	}
}

func TestHandleSleep_ProceedsForActiveStates(t *testing.T) {
	tests := []struct {
		name   string
		status internal.StatusType
	}{
		{"Connecting", internal.StatusConnecting},
		{"Connected", internal.StatusConnected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer()
			state := internal.CtxGetState(s.rootCtx)
			state.Set(tt.status)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.actCancel = cancel

			resp, err := s.handleSleep(ctx)

			require.NoError(t, err)
			assert.NotNil(t, resp)
			assert.True(t, s.sleepTriggeredDown.Load())
		})
	}
}
