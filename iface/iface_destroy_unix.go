//go:build linux || darwin || android || ios
// +build linux darwin android ios

package iface

import (
	"fmt"
	"os/exec"
)

func DestroyInterface(name string) error {
	cmd = exec.Command("ifconfig", name, "destroy")
	if err := cmd.Run(); err != nil {
		cmd := exec.Command("ip", "link", "delete", name)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to destroy interface %s: %w", name, err)
		}
	}

	return nil
}
