package client

import (
	"sync"
	"testing"
)

// The stream status is written by the receive loop and read from other
// goroutines, such as the client's control plane readiness check. Run with
// -race: an unguarded read is reported as a data race.
func TestStreamStatusConcurrentAccess(t *testing.T) {
	c := &GrpcClient{}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			c.notifyStreamConnected()
			c.notifyStreamDisconnected()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = c.StreamConnected()
			_ = c.GetStatus()
		}
	}()
	wg.Wait()
}
