package peer

import (
	"testing"
	"time"
)

func Test_newOfferListener(t *testing.T) {
	dummyOfferAnswer := &OfferAnswer{}
	runChan := make(chan struct{}, 10)

	longRunningFn := func(remoteOfferAnswer *OfferAnswer) {
		time.Sleep(1 * time.Second)
		runChan <- struct{}{}
	}

	hl := NewOfferListener(longRunningFn)

	hl.Notify(dummyOfferAnswer)
	hl.Notify(dummyOfferAnswer)
	hl.Notify(dummyOfferAnswer)

	// Wait for exactly 2 callbacks
	for i := 0; i < 2; i++ {
		select {
		case <-runChan:
		case <-time.After(3 * time.Second):
			t.Fatal("Timeout waiting for callback")
		}
	}

	// Verify no additional callbacks happen
	select {
	case <-runChan:
		t.Fatal("Unexpected additional callback")
	case <-time.After(100 * time.Millisecond):
		t.Log("Correctly received exactly 2 callbacks")
	}
}
