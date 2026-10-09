//go:build unix

package certproof

import (
	"errors"
	"os/exec"
	"syscall"
)

// killHelperGroupOnCancel puts cmd in a process group of its own and kills the whole
// group when cmd's context ends. The helper may run below launchers such as launchctl
// and sudo, which do not pass a kill on, and it keeps the output pipes open, so killing
// only the direct child would leave the helper running and Wait blocked until the
// helper exits on its own, for one waiting on a keychain prompt nobody answers.
func killHelperGroupOnCancel(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	cmd.WaitDelay = helperWaitDelay
}

// startHelper starts cmd. Killing the helper with everything below it is arranged by
// killHelperGroupOnCancel where the helper runs under a launcher.
func startHelper(cmd *exec.Cmd) (func(), error) {
	return func() {}, cmd.Start()
}
