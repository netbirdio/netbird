package inactivity

import (
	"context"
	"testing"
	"time"

	peerid "github.com/netbirdio/netbird/client/internal/peer/id"
)

type MocPeer struct {
}

func (m *MocPeer) ConnID() peerid.ConnID {
	return peerid.ConnID(m)
}

func TestInactivityMonitor(t *testing.T) {
	tCtx, testTimeoutCancel := context.WithTimeout(context.Background(), time.Second*5)
	defer testTimeoutCancel()

	p := &MocPeer{}
	im := NewInactivityMonitor(p.ConnID(), time.Second*2)

	timeoutChan := make(chan peerid.ConnID)

	exitChan := make(chan struct{})

	go func() {
		defer close(exitChan)
		im.Start(tCtx, timeoutChan)
	}()

	select {
	case <-timeoutChan:
	case <-tCtx.Done():
		t.Fatal("timeout")
	}

	select {
	case <-exitChan:
	case <-tCtx.Done():
		t.Fatal("timeout")
	}
}

func TestReuseInactivityMonitor(t *testing.T) {
	p := &MocPeer{}
	im := NewInactivityMonitor(p.ConnID(), time.Second*2)

	timeoutChan := make(chan peerid.ConnID)

	for i := 2; i > 0; i-- {
		exitChan := make(chan struct{})

		testTimeoutCtx, testTimeoutCancel := context.WithTimeout(context.Background(), time.Second*5)

		go func() {
			defer close(exitChan)
			im.Start(testTimeoutCtx, timeoutChan)
		}()

		select {
		case <-timeoutChan:
		case <-testTimeoutCtx.Done():
			t.Fatal("timeout")
		}

		select {
		case <-exitChan:
		case <-testTimeoutCtx.Done():
			t.Fatal("timeout")
		}
		testTimeoutCancel()
	}
}

func TestStopInactivityMonitor(t *testing.T) {
	tCtx, testTimeoutCancel := context.WithTimeout(context.Background(), time.Second*5)
	defer testTimeoutCancel()

	p := &MocPeer{}
	im := NewInactivityMonitor(p.ConnID(), DefaultInactivityThreshold)

	timeoutChan := make(chan peerid.ConnID)

	exitChan := make(chan struct{})

	go func() {
		defer close(exitChan)
		im.Start(tCtx, timeoutChan)
	}()

	go func() {
		time.Sleep(3 * time.Second)
		im.Stop()
	}()

	select {
	case <-timeoutChan:
		t.Fatal("unexpected timeout")
	case <-exitChan:
	case <-tCtx.Done():
		t.Fatal("timeout")
	}
}

func TestPauseInactivityMonitor(t *testing.T) {
	tCtx, testTimeoutCancel := context.WithTimeout(context.Background(), time.Second*10)
	defer testTimeoutCancel()

	p := &MocPeer{}
	trashHold := time.Second * 3
	im := NewInactivityMonitor(p.ConnID(), trashHold)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	timeoutChan := make(chan peerid.ConnID)

	exitChan := make(chan struct{})

	go func() {
		defer close(exitChan)
		im.Start(ctx, timeoutChan)
	}()

	time.Sleep(1 * time.Second) // grant time to start the monitor
	im.PauseTimer()

	// check to do not receive timeout
	thresholdCtx, thresholdCancel := context.WithTimeout(context.Background(), trashHold+time.Second)
	defer thresholdCancel()
	select {
	case <-exitChan:
		t.Fatal("unexpected exit")
	case <-timeoutChan:
		t.Fatal("unexpected timeout")
	case <-thresholdCtx.Done():
		// test ok
	case <-tCtx.Done():
		t.Fatal("test timed out")
	}

	// test reset timer
	im.ResetTimer()

	select {
	case <-tCtx.Done():
		t.Fatal("test timed out")
	case <-exitChan:
		t.Fatal("unexpected exit")
	case <-timeoutChan:
		// expected timeout
	}
}
