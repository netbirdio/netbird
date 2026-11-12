package lifecycle

import (
	"runtime/debug"
	"sync"

	log "github.com/sirupsen/logrus"
)

// StopHandlers collects functions to run once when their owner exits. Embed it
// in a server type to expose OnStop and RunStopHandlers.
type StopHandlers struct {
	mu       sync.Mutex
	stopped  bool
	handlers []func()
}

// OnStop registers fn to run once when the owner stops. Handlers run in
// reverse registration order. A handler registered after the owner has
// stopped runs immediately.
func (h *StopHandlers) OnStop(fn func()) {
	h.mu.Lock()
	stopped := h.stopped
	if !stopped {
		h.handlers = append(h.handlers, fn)
	}
	h.mu.Unlock()

	if stopped {
		runStopHandler(fn)
	}
}

// RunStopHandlers runs every registered handler once, last registered first.
// Later calls are no-ops, so it can be wired to several exit paths at once.
func (h *StopHandlers) RunStopHandlers() {
	h.mu.Lock()
	handlers := h.handlers
	h.handlers = nil
	h.stopped = true
	h.mu.Unlock()

	for i := len(handlers) - 1; i >= 0; i-- {
		runStopHandler(handlers[i])
	}
}

// runStopHandler keeps one panicking handler from skipping the ones still
// pending; on the shutdown path there is no second chance to run them.
func runStopHandler(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("stop handler panicked: %v\n%s", r, debug.Stack())
		}
	}()
	fn()
}
