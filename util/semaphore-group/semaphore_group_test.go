package semaphoregroup

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestSemaphoreGroup(t *testing.T) {
	semGroup := NewSemaphoreGroup(1)
	_ = semGroup.Add(context.Background())

	ctxTimeout, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	t.Cleanup(cancel)

	if err := semGroup.Add(ctxTimeout); err == nil {
		t.Error("Adding to semaphore group should not block")
	}
}

func TestSemaphoreGroupFreeUp(t *testing.T) {
	semGroup := NewSemaphoreGroup(1)
	_ = semGroup.Add(context.Background())
	semGroup.Done()

	ctxTimeout, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	t.Cleanup(cancel)
	if err := semGroup.Add(ctxTimeout); err != nil {
		t.Error(err)
	}
}

func TestSemaphoreGroupCanceledContext(t *testing.T) {
	semGroup := NewSemaphoreGroup(1)
	_ = semGroup.Add(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	if err := semGroup.Add(ctx); err == nil {
		t.Error("Add should return error when context is already canceled")
	}
}

func TestSemaphoreGroupCancelWhileWaiting(t *testing.T) {
	semGroup := NewSemaphoreGroup(1)
	_ = semGroup.Add(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)

	go func() {
		errChan <- semGroup.Add(ctx)
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	if err := <-errChan; err == nil {
		t.Error("Add should return error when context is canceled while waiting")
	}
}

func TestSemaphoreGroupHighConcurrency(t *testing.T) {
	const limit = 10
	const numGoroutines = 100

	semGroup := NewSemaphoreGroup(limit)
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := semGroup.Add(context.Background()); err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			time.Sleep(time.Millisecond)
			semGroup.Done()
		}()
	}

	wg.Wait()

	// Verify all slots were released
	if got := len(semGroup.semaphore); got != 0 {
		t.Errorf("Expected semaphore to be empty, got %d slots occupied", got)
	}
}
