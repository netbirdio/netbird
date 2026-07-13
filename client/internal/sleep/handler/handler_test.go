package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
)

type mockAgent struct {
	upErr     error
	downErr   error
	statusErr error
	status    internal.StatusType
	upCalls   int
}

func (m *mockAgent) Up(_ context.Context) error {
	m.upCalls++
	return m.upErr
}

func (m *mockAgent) Down(_ context.Context) error {
	return m.downErr
}

func (m *mockAgent) Status() (internal.StatusType, error) {
	return m.status, m.statusErr
}

func newHandler(status internal.StatusType) (*SleepHandler, *mockAgent) {
	agent := &mockAgent{status: status}
	return New(agent), agent
}

func TestHandleWakeUp_SkipsWhenFlagFalse(t *testing.T) {
	h, agent := newHandler(internal.StatusIdle)

	err := h.HandleWakeUp(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 0, agent.upCalls, "Up should not be called when flag is false")
}

func TestHandleWakeUp_ResetsFlagBeforeUp(t *testing.T) {
	h, _ := newHandler(internal.StatusIdle)
	h.sleepTriggeredDown = true

	// Even if Up fails, flag should be reset
	_ = h.HandleWakeUp(context.Background())

	assert.False(t, h.sleepTriggeredDown, "flag must be reset before calling Up")
}

func TestHandleWakeUp_CallsUpWhenFlagSet(t *testing.T) {
	h, agent := newHandler(internal.StatusIdle)
	h.sleepTriggeredDown = true

	err := h.HandleWakeUp(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 1, agent.upCalls)
	assert.False(t, h.sleepTriggeredDown)
}

func TestHandleWakeUp_ReturnsErrorFromUp(t *testing.T) {
	h, agent := newHandler(internal.StatusIdle)
	h.sleepTriggeredDown = true
	agent.upErr = errors.New("up failed")

	err := h.HandleWakeUp(context.Background())

	assert.ErrorIs(t, err, agent.upErr)
	assert.False(t, h.sleepTriggeredDown, "flag should still be reset even when Up fails")
}

func TestHandleWakeUp_SecondCallIsNoOp(t *testing.T) {
	h, agent := newHandler(internal.StatusIdle)
	h.sleepTriggeredDown = true

	_ = h.HandleWakeUp(context.Background())
	err := h.HandleWakeUp(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 1, agent.upCalls, "second wakeup should be no-op")
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
			h, _ := newHandler(tt.status)

			err := h.HandleSleep(context.Background())

			require.NoError(t, err)
			assert.False(t, h.sleepTriggeredDown)
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
			h, _ := newHandler(tt.status)

			err := h.HandleSleep(context.Background())

			require.NoError(t, err)
			assert.True(t, h.sleepTriggeredDown)
		})
	}
}

func TestHandleSleep_ReturnsErrorFromStatus(t *testing.T) {
	agent := &mockAgent{statusErr: errors.New("status error")}
	h := New(agent)

	err := h.HandleSleep(context.Background())

	assert.ErrorIs(t, err, agent.statusErr)
	assert.False(t, h.sleepTriggeredDown)
}

func TestHandleSleep_ReturnsErrorFromDown(t *testing.T) {
	agent := &mockAgent{status: internal.StatusConnected, downErr: errors.New("down failed")}
	h := New(agent)

	err := h.HandleSleep(context.Background())

	assert.ErrorIs(t, err, agent.downErr)
	assert.False(t, h.sleepTriggeredDown, "flag should not be set when Down fails")
}
