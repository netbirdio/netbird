package internal

import (
	"context"
	"sync"
)

type StatusType string

const (
	StatusIdle StatusType = "Idle"

	StatusConnecting  StatusType = "Connecting"
	StatusConnected   StatusType = "Connected"
	StatusNeedsLogin  StatusType = "NeedsLogin"
	StatusLoginFailed StatusType = "LoginFailed"
)

// CtxInitState setup context state into the context tree.
//
// This function should be used to initialize context before
// CtxGetState will be executed.
func CtxInitState(ctx context.Context) context.Context {
	return context.WithValue(ctx, stateCtx, &contextState{
		status: StatusIdle,
	})
}

// CtxGetState object to get/update state/errors of process.
func CtxGetState(ctx context.Context) *contextState {
	return ctx.Value(stateCtx).(*contextState)
}

type contextState struct {
	err    error
	status StatusType
	mutex  sync.Mutex
}

func (c *contextState) Set(update StatusType) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.status = update
	c.err = nil
}

func (c *contextState) Status() (StatusType, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.err != nil {
		return "", c.err
	}

	return c.status, nil
}

func (c *contextState) Wrap(err error) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.err = err
	return err
}

type stateKey int

var stateCtx stateKey
