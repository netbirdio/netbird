//go:build windows

package coexist

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// addressChanges signals every unicast address added, changed or removed on
// any adapter. Signals arriving while one is pending are merged.
func addressChanges() (<-chan struct{}, func(), error) {
	ch := make(chan struct{}, 1)
	cb, err := winipcfg.RegisterUnicastAddressChangeCallback(
		func(winipcfg.MibNotificationType, *winipcfg.MibUnicastIPAddressRow) {
			select {
			case ch <- struct{}{}:
			default:
			}
		})
	if err != nil {
		return nil, nil, fmt.Errorf("register for address changes: %w", err)
	}
	stop := func() {
		if err := cb.Unregister(); err != nil {
			log.Debugf("unregister the address change callback: %v", err)
		}
	}
	return ch, stop, nil
}
