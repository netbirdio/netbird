//go:build linux && !android

package iface

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func (w *WGIface) Destroy() error {
	link, err := netlink.LinkByName(w.Name())
	if err != nil {
		return fmt.Errorf("failed to get link by name %s: %w", w.Name(), err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete link %s: %w", w.Name(), err)
	}

	return nil
}
