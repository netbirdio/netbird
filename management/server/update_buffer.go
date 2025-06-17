package server

import (
	"context"
	"sync"
)

type UpdateBuffer struct {
	mu     sync.Mutex
	cond   *sync.Cond
	update *UpdateMessage
	closed bool
}

func NewUpdateBuffer() *UpdateBuffer {
	ub := &UpdateBuffer{}
	ub.cond = sync.NewCond(&ub.mu)
	return ub
}

func (b *UpdateBuffer) Push(update *UpdateMessage) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// the equal case we need because we don't always increment the serial number
	if b.update == nil || update.NetworkMap.Network.Serial >= b.update.NetworkMap.Network.Serial {
		b.update = update
		b.cond.Signal()
	}
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
