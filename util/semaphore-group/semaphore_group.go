package semaphoregroup

import (
	"context"
	"sync"
)

// SemaphoreGroup is a custom type that combines sync.WaitGroup and a semaphore.
type SemaphoreGroup struct {
	waitGroup sync.WaitGroup
	semaphore chan struct{}
}

// NewSemaphoreGroup creates a new SemaphoreGroup with the specified semaphore limit.
func NewSemaphoreGroup(limit int) *SemaphoreGroup {
	return &SemaphoreGroup{
		semaphore: make(chan struct{}, limit),
	}
}

// Add increments the internal WaitGroup counter and acquires a semaphore slot.
func (sg *SemaphoreGroup) Add(ctx context.Context) {
	sg.waitGroup.Add(1)

	// Acquire semaphore slot
	select {
	case <-ctx.Done():
		return
	case sg.semaphore <- struct{}{}:
	}
}

// Done decrements the internal WaitGroup counter and releases a semaphore slot.
func (sg *SemaphoreGroup) Done(ctx context.Context) {
	sg.waitGroup.Done()

	// Release semaphore slot
	select {
	case <-ctx.Done():
		return
	case <-sg.semaphore:
	}
}

// Wait waits until the internal WaitGroup counter is zero.
func (sg *SemaphoreGroup) Wait() {
	sg.waitGroup.Wait()
}
