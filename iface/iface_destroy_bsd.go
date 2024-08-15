//go:build darwin || dragonfly || freebsd || netbsd || openbsd
// +build darwin dragonfly freebsd netbsd openbsd

package iface

import (
	"fmt"
	"os/exec"
)

func DestroyInterface(name string) error {
	_, err := exec.Command("ifconfig", name, "destroy").CombinedOutput()
	if err != nil {
		_, err := exec.Command("ip", "link", "delete", name).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to destroy interface %s: %w", name, err)
		}
	}

	return nil
}
