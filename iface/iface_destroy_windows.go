//go:build windows

package iface

import (
	"fmt"
	"os/exec"

	"github.com/netbirdio/netbird/client/firewall/uspfilter"
)

func (w *WGIface) Destroy() error {
	netshCmd := uspfilter.GetSystem32Command("netsh")
	out, err := exec.Command(netshCmd, "interface", "set", "interface", w.Name(), "admin=disable").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove interface %s: %w - %s", w.Name(), err, out)
	}
	return nil
}
