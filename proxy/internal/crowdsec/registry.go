package crowdsec

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

// Registry manages a single shared Bouncer instance with reference counting.
// The bouncer starts when the first service acquires it and stops when the
// last service releases it.
type Registry struct {
	mu      sync.Mutex
	bouncer *Bouncer
	refs    map[types.ServiceID]struct{}
	apiURL  string
	apiKey  string
	logger  *log.Entry
	cancel  context.CancelFunc
}

// NewRegistry creates a registry. The bouncer is not started until Acquire is called.
func NewRegistry(apiURL, apiKey string, logger *log.Entry) *Registry {
	return &Registry{
		apiURL: apiURL,
		apiKey: apiKey,
		logger: logger,
		refs:   make(map[types.ServiceID]struct{}),
	}
}

// Available returns true when the LAPI URL and API key are configured.
func (r *Registry) Available() bool {
	return r.apiURL != "" && r.apiKey != ""
}

// Acquire registers svcID as a consumer and starts the bouncer if this is the
// first consumer. Returns the shared Bouncer (which implements the restrict
// package's CrowdSecChecker interface). Returns nil if not Available.
func (r *Registry) Acquire(svcID types.ServiceID) *Bouncer {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.Available() {
		return nil
	}

	if _, exists := r.refs[svcID]; exists {
		return r.bouncer
	}

	if r.bouncer == nil {
		r.startLocked()
	}

	// startLocked may fail, leaving r.bouncer nil.
	if r.bouncer == nil {
		return nil
	}

	r.refs[svcID] = struct{}{}
	return r.bouncer
}

// Release removes svcID as a consumer. Stops the bouncer when the last
// consumer releases.
func (r *Registry) Release(svcID types.ServiceID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.refs, svcID)

	if len(r.refs) == 0 && r.bouncer != nil {
		r.stopLocked()
	}
}

func (r *Registry) startLocked() {
	b := NewBouncer(r.apiURL, r.apiKey, r.logger)

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel

	if err := b.Start(ctx); err != nil {
		r.logger.Errorf("failed to start CrowdSec bouncer: %v", err)
		cancel()
		return
	}

	r.bouncer = b
	r.logger.Info("CrowdSec bouncer started")
}

func (r *Registry) stopLocked() {
	r.bouncer.Stop()
	r.cancel()
	r.bouncer = nil
	r.cancel = nil
	r.logger.Info("CrowdSec bouncer stopped")
}
