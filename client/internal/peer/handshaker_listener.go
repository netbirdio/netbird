package peer

import (
	"sync"
)

type callbackFunc func(remoteOfferAnswer *OfferAnswer)

func (oa *OfferAnswer) SessionIDString() string {
	if oa.SessionID == nil {
		return "unknown"
	}
	return oa.SessionID.String()
}

type AsyncOfferListener struct {
	fn      callbackFunc
	running bool
	latest  *OfferAnswer
	mu      sync.Mutex
}

func NewAsyncOfferListener(fn callbackFunc) *AsyncOfferListener {
	return &AsyncOfferListener{
		fn: fn,
	}
}

func (o *AsyncOfferListener) Notify(remoteOfferAnswer *OfferAnswer) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Store the latest offer
	o.latest = remoteOfferAnswer

	// If already running, the running goroutine will pick up this latest value
	if o.running {
		return
	}

	// Start processing
	o.running = true

	// Process in a goroutine to avoid blocking the caller
	go func(remoteOfferAnswer *OfferAnswer) {
		for {
			o.fn(remoteOfferAnswer)

			o.mu.Lock()
			if o.latest == nil {
				// No more work to do
				o.running = false
				o.mu.Unlock()
				return
			}
			remoteOfferAnswer = o.latest
			// Clear the latest to mark it as being processed
			o.latest = nil
			o.mu.Unlock()
		}
	}(remoteOfferAnswer)
}
