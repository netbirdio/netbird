//go:build windows
// +build windows

package iface

import (
	"os/exec"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/uspfilter"
)

func DestroyInterface(name string) error {
	netshCmd := uspfilter.GetSystem32Command("netsh")
	_, err := exec.Command(netshCmd, "interface", "set", "interface", name, "admin=disable").CombinedOutput()
	if err != nil {
		log.Errorf("failed to disable interface %s: %v", name, err)
		return err
	}
	return nil
}
