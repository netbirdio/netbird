//go:build windows

package iface

import (
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

func (w *WGIface) Destroy() error {
	netshCmd := GetSystem32Command("netsh")
	out, err := exec.Command(netshCmd, "interface", "set", "interface", w.Name(), "admin=disable").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove interface %s: %w - %s", w.Name(), err, out)
	}
	return nil
}

// GetSystem32Command checks if a command can be found in the system path and returns it. In case it can't find it
// in the path it will return the full path of a command assuming C:\windows\system32 as the base path.
func GetSystem32Command(command string) string {
	_, err := exec.LookPath(command)
	if err == nil {
		return command
	}

	log.Tracef("Command %s not found in PATH, using C:\\windows\\system32\\%s.exe path", command, command)

	return "C:\\windows\\system32\\" + command + ".exe"
}
