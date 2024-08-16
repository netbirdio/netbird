//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package iface

import (
	"fmt"
	"os/exec"
)

func (w *WGIface) Destroy() error {
	out, err := exec.Command("ifconfig", w.Name(), "destroy").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove interface %s: %w - %s", w.Name(), err, out)
	}

	return nil
}
