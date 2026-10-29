package coexist

import (
	"context"
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/instance"
)

// settleDelay groups the burst of notifications an adapter coming up produces
// into one check.
const settleDelay = time.Second

// WatchOverlay runs while a secondary installation is connected and returns the
// first overlap between its overlay and an address that another NetBird adapter
// gets later, for example when the primary connects after it. It returns false
// when ctx ends first, and at once for a primary, which is not checked.
func WatchOverlay(ctx context.Context, inst instance.Instance, ownIface string, addr wgaddr.Address) (OverlayConflict, bool) {
	if !inst.IsSecondary() {
		return OverlayConflict{}, false
	}
	changes, stop, err := addressChanges()
	if err != nil {
		log.Warnf("watch address changes for overlapping overlays: %v", err)
		return OverlayConflict{}, false
	}
	defer stop()

	list := func() ([]Adapter, error) { return OtherOverlayAdapters(ownIface) }
	return watchOverlay(ctx, changes, settleDelay, OverlayPrefixes(addr), list)
}

// watchOverlay checks once right away, covering the time between the connect
// check and the subscription, then after every change. A failed listing does
// not end the watch: the tunnel is up, and the next change checks again.
func watchOverlay(ctx context.Context, changes <-chan struct{}, settle time.Duration, own []netip.Prefix,
	list func() ([]Adapter, error)) (OverlayConflict, bool) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return OverlayConflict{}, false
		case <-changes:
			timer.Reset(settle)
		case <-timer.C:
			others, err := list()
			if err != nil {
				log.Warnf("list NetBird adapters to check for an overlapping overlay: %v", err)
				continue
			}
			if c, ok := FindOverlayConflict(own, others); ok {
				return c, true
			}
		}
	}
}
