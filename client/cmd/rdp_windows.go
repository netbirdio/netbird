//go:build windows

package cmd

import (
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

// launchRDPClient launches the native Windows Remote Desktop client (mstsc.exe).
func launchRDPClient(peerIP string) error {
	mstscPath, err := exec.LookPath("mstsc.exe")
	if err != nil {
		return fmt.Errorf("mstsc.exe not found: %w", err)
	}

	cmd := exec.Command(mstscPath, fmt.Sprintf("/v:%s", peerIP))
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start mstsc.exe: %w", err)
	}

	log.Debugf("launched mstsc.exe (PID %d) connecting to %s", cmd.Process.Pid, peerIP)

	// Don't wait for mstsc to exit - it runs independently
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Debugf("mstsc.exe exited: %v", err)
		}
	}()

	return nil
}
