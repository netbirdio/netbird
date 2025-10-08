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

	if b.update == nil || update.Update.NetworkMap.Serial > b.update.Update.NetworkMap.Serial || b.update.Update.NetworkMap.Serial == 0 {
		if b.update == nil {
			b.metrics.CountBufferPush()
		} else {
			b.metrics.CountBufferOverwrite()
		}

		b.update = update
		b.cond.Signal()

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
