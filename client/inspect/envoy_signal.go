//go:build !windows

package inspect

import (
	"os"
	"syscall"
)

// signalReload sends SIGHUP to the envoy process to trigger config reload.
func signalReload(p *os.Process) error {
	return p.Signal(syscall.SIGHUP)
}
