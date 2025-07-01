package server

import (
	"context"
	"sync"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

type UpdateBuffer struct {
	mu      sync.Mutex
	cond    *sync.Cond
	update  *UpdateMessage
	closed  bool
	metrics *telemetry.UpdateChannelMetrics
}

func NewUpdateBuffer(metrics *telemetry.UpdateChannelMetrics) *UpdateBuffer {
	ub := &UpdateBuffer{metrics: metrics}
	ub.cond = sync.NewCond(&ub.mu)
	return ub
}

func (b *UpdateBuffer) Push(update *UpdateMessage) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.update != nil && update.Update.NetbirdConfig != nil {
		if update.Update.NetbirdConfig.Relay != nil {
			b.update.Update.NetbirdConfig.Relay = update.Update.NetbirdConfig.Relay
		}
		if update.Update.NetbirdConfig.Signal != nil {
			b.update.Update.NetbirdConfig.Signal = update.Update.NetbirdConfig.Signal
		}
		if update.Update.NetbirdConfig.Flow != nil {
			b.update.Update.NetbirdConfig.Flow = update.Update.NetbirdConfig.Flow
		}
		if update.Update.NetbirdConfig.Stuns != nil {
			b.update.Update.NetbirdConfig.Stuns = update.Update.NetbirdConfig.Stuns
		}
		if update.Update.NetbirdConfig.Turns != nil {
			b.update.Update.NetbirdConfig.Turns = update.Update.NetbirdConfig.Turns
		}
	}

	// the equal case we need because we don't always increment the serial number
	if b.update == nil || update.Update.NetworkMap.Serial > b.update.Update.NetworkMap.Serial || b.update.Update.NetworkMap.Serial == 0 {
		b.update = update
		b.cond.Signal()
		if b.update == nil {
			b.metrics.CountBufferPush()
			return
		}

		b.metrics.CountBufferOverwrite()
		return
	}

	b.metrics.CountBufferIgnore()
}

func (b *UpdateBuffer) Pop(ctx context.Context) (*UpdateMessage, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for b.update == nil && !b.closed {
		waitCh := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				b.cond.Broadcast()
			case <-waitCh:
				// noop
			}
		}()
		b.cond.Wait()
		close(waitCh)
	}

	if b.closed {
		return nil, false
	}
	msg := b.update
	b.update = nil
	return msg, true
}

func (b *UpdateBuffer) Close() {
	b.mu.Lock()
	b.closed = true
	b.cond.Broadcast()
	b.mu.Unlock()
}
