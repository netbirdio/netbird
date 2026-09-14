package lifecycle

import "sync"

// StopHandlers collects functions to run once when their owner exits. Embed it
// in a server type to expose OnStop and RunStopHandlers.
type StopHandlers struct {
	mu       sync.Mutex
	handlers []func()
}

// OnStop registers fn to run once when the owner stops. Handlers run in
// reverse registration order.
func (h *StopHandlers) OnStop(fn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handlers = append(h.handlers, fn)
}

// RunStopHandlers runs every registered handler once, last registered first.
// Later calls are no-ops, so it can be wired to several exit paths at once.
func (h *StopHandlers) RunStopHandlers() {
	h.mu.Lock()
	handlers := h.handlers
	h.handlers = nil
	h.mu.Unlock()

	for i := len(handlers) - 1; i >= 0; i-- {
		handlers[i]()
	}
}
