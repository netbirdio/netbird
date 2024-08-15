//go:build windows
// +build windows

package iface

import (
	"os/exec"

	log "github.com/sirupsen/logrus"
)

func DestroyInterface(name string) error {
	cmd := exec.Command("netsh", "interface", "set", "interface", name, "admin=disable")
	if err := cmd.Run(); err != nil {
		log.Errorf("failed to disable interface %s: %v", name, err)
		return err
	}
	return nil
}
