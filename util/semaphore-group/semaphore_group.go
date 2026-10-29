package semaphoregroup

import (
	"context"
)

// SemaphoreGroup is a custom type that combines sync.WaitGroup and a semaphore.
type SemaphoreGroup struct {
	semaphore chan struct{}
}

// NewSemaphoreGroup creates a new SemaphoreGroup with the specified semaphore limit.
func NewSemaphoreGroup(limit int) *SemaphoreGroup {
	return &SemaphoreGroup{
		semaphore: make(chan struct{}, limit),
	}
}

// Add acquire a slot
func (sg *SemaphoreGroup) Add(ctx context.Context) error {
	// Acquire semaphore slot
	select {
	case <-ctx.Done():
		return ctx.Err()
	case sg.semaphore <- struct{}{}:
		return nil
	}
}

// Done releases a slot. Must be called after a successful Add.
func (sg *SemaphoreGroup) Done() {
	<-sg.semaphore
}
