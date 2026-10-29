package auth

import (
	"context"
	"sync"
	"time"
)

// PendingFlow stores an in-progress OAuth flow between the RPC that
// initiates it (returns the verification URI to the UI) and the RPC
// that waits for the user to complete it. The flow handle, the
// device-code info, and the absolute expiry are kept together so the
// waiting RPC can validate the device code and reuse the same flow.
//
// PendingFlow is safe for concurrent use; callers must not access the
// stored fields directly.
type PendingFlow struct {
	mu         sync.Mutex
	flow       OAuthFlow
	info       AuthFlowInfo
	expiresAt  time.Time
	waitCancel context.CancelFunc
}

// NewPendingFlow returns an empty PendingFlow ready to be populated by Set.
func NewPendingFlow() *PendingFlow {
	return &PendingFlow{}
}

// Set stores the flow and its authorization info, computing the absolute
// expiry from info.ExpiresIn (seconds, as returned by the IdP).
func (p *PendingFlow) Set(flow OAuthFlow, info AuthFlowInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.flow = flow
	p.info = info
	p.expiresAt = time.Now().Add(time.Duration(info.ExpiresIn) * time.Second)
}

// Get returns the stored flow, info, and whether a flow is currently
// pending. Returns (nil, zero, false) after Clear or before Set.
func (p *PendingFlow) Get() (OAuthFlow, AuthFlowInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.flow == nil {
		return nil, AuthFlowInfo{}, false
	}
	return p.flow, p.info, true
}

// ExpiresAt returns the absolute expiry of the pending flow. Returns
// the zero time when no flow is pending.
func (p *PendingFlow) ExpiresAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.expiresAt
}

// SetWaitCancel records the cancel function for the goroutine currently
// blocked in WaitToken so a new RequestAuth can preempt it.
func (p *PendingFlow) SetWaitCancel(cancel context.CancelFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.waitCancel = cancel
}

// CancelWait invokes and clears the stored wait-cancel, if any. Safe to
// call when no wait is in progress.
func (p *PendingFlow) CancelWait() {
	p.mu.Lock()
	cancel := p.waitCancel
	p.waitCancel = nil
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Clear resets the pending flow to empty. Any stored wait-cancel is
// dropped without being invoked — call CancelWait first if the waiting
// goroutine must be stopped.
func (p *PendingFlow) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.flow = nil
	p.info = AuthFlowInfo{}
	p.expiresAt = time.Time{}
	p.waitCancel = nil
}
