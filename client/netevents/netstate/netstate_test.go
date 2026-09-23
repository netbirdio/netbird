package netstate

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStateIsOnline(t *testing.T) {
	assert.True(t, New().IsOnline(), "a fresh State should start online")
}

func TestSetTogglesOnlineState(t *testing.T) {
	s := New()

	s.Set(false)
	assert.False(t, s.IsOnline(), "state should be offline after Set(false)")

	s.Set(true)
	assert.True(t, s.IsOnline(), "state should be online after Set(true)")
}

func TestWaitReturnsImmediatelyWhenOnline(t *testing.T) {
	s := New()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	waited, err := s.Wait(ctx)
	require.NoError(t, err)
	assert.False(t, waited, "Wait should not block when the network is online")
}

func TestWaitBlocksUntilOnline(t *testing.T) {
	s := New()
	s.Set(false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := make(chan bool, 1)
	go func() {
		waited, err := s.Wait(ctx)
		if err != nil {
			result <- false
			return
		}
		result <- waited
	}()

	// Verify Wait is actually blocking while offline
	select {
	case <-result:
		t.Fatal("Wait should block while the network is offline")
	case <-time.After(100 * time.Millisecond):
	}

	s.Set(true)

	select {
	case waited := <-result:
		assert.True(t, waited, "Wait should report that it had to wait for the network")
	case <-time.After(2 * time.Second):
		t.Fatal("Wait should return promptly after the network becomes available")
	}
}

func TestWaitReturnsOnContextCancel(t *testing.T) {
	s := New()
	s.Set(false)

	ctx, cancel := context.WithCancel(context.Background())

	result := make(chan error, 1)
	go func() {
		_, err := s.Wait(ctx)
		result <- err
	}()

	cancel()

	select {
	case err := <-result:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("Wait should return promptly after context cancellation")
	}
}

func TestWaitWakesAllWaiters(t *testing.T) {
	s := New()
	s.Set(false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const waiters = 10
	var wg sync.WaitGroup
	results := make(chan bool, waiters)
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			waited, err := s.Wait(ctx)
			if err != nil {
				results <- false
				return
			}
			results <- waited
		}()
	}

	time.Sleep(100 * time.Millisecond)
	s.Set(true)
	wg.Wait()

	close(results)
	count := 0
	for waited := range results {
		assert.True(t, waited, "every waiter should report that it waited")
		count++
	}
	assert.Equal(t, waiters, count, "all waiters should have returned")
}

func TestNilStateReadsAreNoops(t *testing.T) {
	var s *State

	assert.True(t, s.IsOnline(), "nil State should report online")

	waited, err := s.Wait(context.Background())
	require.NoError(t, err)
	assert.False(t, waited, "nil State's Wait should not block")
}

func TestConcurrentSetAndWait(t *testing.T) {
	s := New()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.Set(j%2 == 0)
				s.IsOnline()
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if _, err := s.Wait(ctx); err != nil {
					return
				}
			}
		}()
	}

	wg.Wait()
}
