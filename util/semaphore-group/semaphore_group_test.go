package semaphoregroup

import (
	"testing"
	"time"
)

func TestSemaphoreGroup(t *testing.T) {
	semGroup := NewSemaphoreGroup(2)

	for i := 0; i < 5; i++ {
		semGroup.Add()
		go func(id int) {
			defer semGroup.Done()

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
