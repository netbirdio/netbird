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

	if b.update == nil {
		b.update = update
		b.cond.Signal()
		b.metrics.CountBufferPush()
		return
	}

	// the equal case we need because we don't always increment the serial number
	if update.NetworkMap.Network.Serial >= b.update.NetworkMap.Network.Serial {
		b.update = update
		b.cond.Signal()
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
			b.cond.Wait()
			close(waitCh)
		}()

		b.mu.Unlock()
		select {
		case <-ctx.Done():
			b.mu.Lock()
			return nil, false
		case <-waitCh:
			// Wakeup due to Push() or Close()
		}
		b.mu.Lock()
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
