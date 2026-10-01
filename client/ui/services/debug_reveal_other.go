//go:build !android && !ios && !freebsd && !js && !windows

package services

import (
	"os/exec"
	"path/filepath"
	"runtime"
)

// revealFile opens the OS file manager focused on path.
func revealFile(path string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("open", "-R", path)
	} else {
		cmd = exec.Command("xdg-open", filepath.Dir(path))
	}
	return cmd.Start()
}
