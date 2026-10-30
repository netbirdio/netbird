package internal

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCtxGetState_NilContext(t *testing.T) {
	var nilCtx context.Context
	//nolint:staticcheck
	state := CtxGetState(nilCtx)
	require.NotNil(t, state, "CtxGetState(nil) must return a non-nil default contextState")
	status, err := state.Status()
	assert.NoError(t, err, "default state should not have error")
	assert.Equal(t, StatusIdle, status, "default state should be StatusIdle")
}

func TestCtxGetState_UninitializedContext(t *testing.T) {
	ctx := context.Background()
	state := CtxGetState(ctx)
	require.NotNil(t, state, "CtxGetState on uninitialized context must return a non-nil default contextState")
	status, err := state.Status()
	assert.NoError(t, err, "default state should not have error")
	assert.Equal(t, StatusIdle, status, "default state should be StatusIdle")
}

func TestCtxGetState_InitializedContext(t *testing.T) {
	ctx := CtxInitState(context.Background())
	state := CtxGetState(ctx)
	require.NotNil(t, state, "CtxGetState on initialized context must return state")

	state.Set(StatusConnected)
	status, err := state.Status()
	assert.NoError(t, err, "status check should succeed")
	assert.Equal(t, StatusConnected, status, "status should be StatusConnected")
}
