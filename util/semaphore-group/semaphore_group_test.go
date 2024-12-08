package semaphoregroup

import (
	"context"
	"testing"
	"time"
)

func TestSemaphoreGroup(t *testing.T) {
	semGroup := NewSemaphoreGroup(2)

	for i := 0; i < 5; i++ {
		semGroup.Add(context.Background())
		go func(id int) {
			defer semGroup.Done(context.Background())

			got := len(semGroup.semaphore)
			if got == 0 {
				t.Errorf("Expected semaphore length > 0 , got 0")
			}

			time.Sleep(time.Millisecond)
			t.Logf("Goroutine %d is running\n", id)
		}(i)
	}

	semGroup.Wait()

	want := 0
	got := len(semGroup.semaphore)
	if got != want {
		t.Errorf("Expected semaphore length %d, got %d", want, got)
	}
}

func TestSemaphoreGroupContext(t *testing.T) {
	semGroup := NewSemaphoreGroup(1)
	semGroup.Add(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	t.Cleanup(cancel)
	rChan := make(chan struct{})

	go func() {
		semGroup.Add(ctx)
		rChan <- struct{}{}
	}()
	select {
	case <-rChan:
	case <-time.NewTimer(2 * time.Second).C:
		t.Error("Adding to semaphore group should not block when context is not done")
	}

	semGroup.Done(context.Background())

	ctxDone, cancelDone := context.WithTimeout(context.Background(), 1*time.Second)
	t.Cleanup(cancelDone)
	go func() {
		semGroup.Done(ctxDone)
		rChan <- struct{}{}
	}()
	select {
	case <-rChan:
	case <-time.NewTimer(2 * time.Second).C:
		t.Error("Releasing from semaphore group should not block when context is not done")
	}
}
