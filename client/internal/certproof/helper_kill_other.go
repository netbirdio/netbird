//go:build !unix && !windows

package certproof

import "os/exec"

// startHelper starts cmd.
func startHelper(cmd *exec.Cmd) (func(), error) {
	return func() {}, cmd.Start()
}
