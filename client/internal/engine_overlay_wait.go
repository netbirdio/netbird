//go:build !ios

package internal

import "net/netip"

// overlayWaiter carries no state off iOS. Every other platform assigns the
// overlay address in the same call chain that creates the interface, or hands
// the engine an interface that already carries it, so a listener bound right
// after has nothing to wait for. See the iOS variant for what the wait is.
type overlayWaiter struct{}

// overlayAddrReady reports whether ip can be bound. Always true here.
func (e *Engine) overlayAddrReady(netip.Addr) bool {
	return true
}

// armOverlayWatch has nothing to watch here and is never reached, since
// overlayAddrReady never refuses.
func (e *Engine) armOverlayWatch(string, overlayRebind) {}
